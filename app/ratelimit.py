"""rate limiting for POST /api/refund-requests (Sargis).

every request that gets through can cost a Claude call, so there's a per-IP limit and global limits that
don't care about IPs at all. rotating IPs gets you around the first, never the second.

counters live in the same database as the casework store (postgres on vercel, sqlite locally), because
vercel runs several instances and in-memory counters would each only see their own traffic.
if the counters can't be read or written we fail closed with a 503: the control store sits in the same
database, so the request would fail anyway, just after spending a Claude call.
"""
import ipaddress
import os
import sqlite3
import threading
import time

from fastapi import HTTPException, Request

from app.casework.store import db_path
from app.controls.pg import PgConn, is_pg_url
from app.monitoring.audit import log_event

# (window in seconds, max requests). constants in code, never from a request or the environment
PER_IP = (60, 30)                        # generous, a whole team on one campus IP stays under it
GLOBAL = (('global:minute', 60, 120),     # at most 2 planner calls a second, however many IPs
          ('global:day', 86400, 2000))    # and a ceiling on the daily Claude bill

MINUTE_ROWS_KEPT = 3600                   # cleanup: minute counters older than an hour go
DAY_ROWS_KEPT = 2 * 86400                 # daily counters stay two days

SCHEMA = """
CREATE TABLE IF NOT EXISTS rate_counters(
  bucket TEXT NOT NULL, window_start BIGINT NOT NULL, hits INTEGER NOT NULL,
  PRIMARY KEY(bucket, window_start));
"""

_HIT = ('INSERT INTO rate_counters(bucket, window_start, hits) VALUES (?, ?, 1) '
        'ON CONFLICT(bucket, window_start) DO UPDATE SET hits = rate_counters.hits + 1 RETURNING hits')

_now = time.time                          # tests swap this out


class RateLimitStore:
    def __init__(self, path=':memory:'):
        self.path = path
        self.lock = threading.RLock()
        if is_pg_url(path):
            self.conn = PgConn(path)
            self.conn.execute_script(SCHEMA)
            return
        if path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        if path != ':memory:':
            self.conn.execute('PRAGMA journal_mode = WAL')
        self.conn.executescript(SCHEMA)

    def hit(self, bucket, window_start):
        """count one request and return the new total. one atomic upsert, so instances can't race."""
        with self.lock:
            return self.conn.execute(_HIT, (bucket, window_start)).fetchone()[0]

    def cleanup(self, now):
        with self.lock:
            self.conn.execute("DELETE FROM rate_counters WHERE bucket != 'global:day' AND window_start < ?",
                              (now - MINUTE_ROWS_KEPT,))
            self.conn.execute("DELETE FROM rate_counters WHERE bucket = 'global:day' AND window_start < ?",
                              (now - DAY_ROWS_KEPT,))

    def close(self):
        with self.lock:
            self.conn.close()


_lock = threading.Lock()
_state = {}


def get_rate_store():
    path = db_path()
    with _lock:
        if _state.get('path') != path:
            if _state.get('store') is not None:
                _state['store'].close()
            _state.update(store=RateLimitStore(path), path=path)
        return _state['store']


def _reset_for_tests():
    with _lock:
        if _state.get('store') is not None:
            _state['store'].close()
        _state.clear()


def client_key(request):
    """which per-IP bucket a request counts against.

    on vercel it's x-real-ip, which vercel's docs say it overwrites so clients can't spoof it (see CLAUDE.md,
    still to be checked on a preview deploy). locally it's the direct connection, and X-Forwarded-For and
    friends are ignored. anything that isn't one clean IP lands in one shared bucket, so junk can't mint
    fresh buckets. ipv6 is bucketed per /64 since one client usually owns the whole /64."""
    if os.environ.get('VERCEL'):
        raw = request.headers.get('x-real-ip', '')
    else:
        raw = request.client.host if request.client else ''
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return 'ip:unknown'
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6:
        return 'ip6:%s' % ipaddress.ip_network('%s/64' % ip, strict=False)
    return 'ip:%s' % ip


def check(key):
    """None if the request may go on, else (bucket, limit, hits, retry_after seconds).

    the IP goes first and the global counters only move for requests the IP limit let through, so one
    flooding IP can't eat more of the global budget than its own share."""
    now = int(_now())
    store = get_rate_store()
    for bucket, window, limit in ((key,) + PER_IP,) + GLOBAL:
        start = now - now % window
        hits = store.hit(bucket, start)
        if bucket == 'global:minute' and hits == 1:
            store.cleanup(now)            # first request of a new minute, so this runs about once a minute
        if hits > limit:
            return bucket, limit, hits, start + window - now
    return None


def refund_rate_limit(request: Request):
    """FastAPI dependency. runs before the endpoint, so a blocked request never reaches the scan or Claude."""
    key = client_key(request)
    try:
        blocked = check(key)
    except Exception as e:                # fail closed, see the module docstring
        log_event('rate-limit', 'rate_limit_unavailable', severity='high', client=key, error=type(e).__name__)
        raise HTTPException(status_code=503, detail='try again later')
    if blocked is None:
        return
    bucket, limit, hits, retry_after = blocked
    if hits == limit + 1:                 # once per bucket per window, so a flood can't flood the log too
        log_event('rate-limit', 'rate_limited', severity='medium', client=key,
                  limit='ip' if bucket == key else bucket, max_requests=limit, retry_after=retry_after)
    raise HTTPException(status_code=429, headers={'Retry-After': str(retry_after)},
                        detail='Too many requests. Please try again in %d seconds.' % retry_after)
