"""rate limiting on POST /api/refund-requests: per IP, global per minute and per day, and fail closed."""
import sqlite3

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from tests.fakes import FixedPlanner

DAY = 1_800_000_000 - 1_800_000_000 % 86400
T0 = DAY + 1000                                  # 40 seconds into a minute, well inside the day


def form():
    return {'customer_id': 'C-1', 'transaction_id': 'T-1002', 'amount': '5.00', 'reason': 'damaged'}


@pytest.fixture
def env(isolated_paths, monkeypatch):
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(isolated_paths / 'controls.db'))
    monkeypatch.delenv('TRUSTISSUES_CASEWORK_DB', raising=False)
    monkeypatch.delenv('VERCEL', raising=False)
    from app import casework, ratelimit
    from app.controls import gate
    import app.main as main
    for reset in (gate._reset_for_tests, casework._reset_for_tests, ratelimit._reset_for_tests):
        reset()
    # small limits so the tests stay quick. the real ones are checked in test_real_limits
    monkeypatch.setattr(ratelimit, 'PER_IP', (60, 3))
    monkeypatch.setattr(ratelimit, 'GLOBAL', (('global:minute', 60, 5), ('global:day', 86400, 8)))
    clock = [T0]
    monkeypatch.setattr(ratelimit, '_now', lambda: clock[0])
    monkeypatch.setattr(main, 'LOG_DIR', str(isolated_paths))
    planner = FixedPlanner()
    monkeypatch.setattr(main.orchestrator, 'planner', planner)
    yield TestClient(main.app), planner, clock, ratelimit
    for reset in (gate._reset_for_tests, casework._reset_for_tests, ratelimit._reset_for_tests):
        reset()


def post(client, ip=None, **headers):
    if ip:
        headers['x-real-ip'] = ip
    return client.post('/api/refund-requests', json=form(), headers=headers)


def events(action):
    from app.monitoring.audit import get_audit_log
    return get_audit_log().read(action=action)


def test_real_limits():
    from app import ratelimit
    assert ratelimit.PER_IP == (60, 30)
    assert ratelimit.GLOBAL == (('global:minute', 60, 120), ('global:day', 86400, 2000))


def test_per_ip_limit_with_retry_after(env, monkeypatch):
    client, _, _, _ = env
    monkeypatch.setenv('VERCEL', '1')
    assert [post(client, '203.0.113.7').status_code for _ in range(3)] == [200, 200, 200]
    r = post(client, '203.0.113.7')
    assert r.status_code == 429
    assert r.headers['retry-after'] == '20'                         # 40 seconds into the minute
    assert r.json() == {'detail': 'Too many requests. Please try again in 20 seconds.'}
    assert r.headers['x-content-type-options'] == 'nosniff'         # security headers still on
    assert post(client, '198.51.100.1').status_code == 200          # other people are fine


def test_new_minute_resets_the_ip_limit(env, monkeypatch):
    client, _, clock, _ = env
    monkeypatch.setenv('VERCEL', '1')
    for _ in range(4):
        post(client, '203.0.113.7')
    clock[0] += 20
    assert post(client, '203.0.113.7').status_code == 200


def test_rotating_ips_still_hits_the_global_minute_limit(env, monkeypatch):
    client, _, _, _ = env
    monkeypatch.setenv('VERCEL', '1')
    codes = [post(client, '203.0.113.%d' % i).status_code for i in range(1, 8)]
    assert codes == [200] * 5 + [429, 429]
    [e] = events('rate_limited')
    assert e['limit'] == 'global:minute'


def test_global_day_limit(env, monkeypatch):
    client, _, clock, _ = env
    monkeypatch.setenv('VERCEL', '1')
    codes = []
    for i in range(10):
        clock[0] = T0 + 60 * i                                       # a new minute each time
        codes.append(post(client, '203.0.113.%d' % i).status_code)
    assert codes == [200] * 8 + [429, 429]
    r = post(client, '198.51.100.1')
    assert int(r.headers['retry-after']) > 80000                     # back tomorrow
    assert events('rate_limited')[0]['limit'] == 'global:day'


def test_blocked_ip_does_not_use_up_the_global_budget(env, monkeypatch):
    client, _, _, _ = env
    monkeypatch.setenv('VERCEL', '1')
    for _ in range(10):
        post(client, '203.0.113.7')                                  # 3 allowed, 7 blocked per IP
    assert post(client, '198.51.100.1').status_code == 200           # global has 2 left, not 0


def test_spoofed_headers_are_ignored_locally(env):
    client, _, _, _ = env
    codes = [post(client, None, **{'X-Forwarded-For': '10.0.0.%d' % i, 'X-Real-IP': '10.1.0.%d' % i}).status_code
             for i in range(4)]
    assert codes == [200, 200, 200, 429]


def _request(headers=(), client=('10.0.0.5', 50000)):
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'client': client,
                    'headers': [(k.lower().encode(), v.encode()) for k, v in headers]})


def test_client_key_locally_is_the_direct_connection(monkeypatch):
    from app.ratelimit import client_key
    monkeypatch.delenv('VERCEL', raising=False)
    spoof = [('X-Forwarded-For', '1.2.3.4'), ('X-Real-IP', '1.2.3.4'), ('X-Vercel-Forwarded-For', '1.2.3.4')]
    assert client_key(_request(spoof)) == 'ip:10.0.0.5'
    assert client_key(_request(client=None)) == 'ip:unknown'


@pytest.mark.parametrize('value,key', [
    ('203.0.113.7', 'ip:203.0.113.7'),
    (' 203.0.113.7 ', 'ip:203.0.113.7'),
    ('203.0.113.7, 10.0.0.1', 'ip:unknown'),                         # a list is not one clean ip
    ('', 'ip:unknown'),
    ('not-an-ip', 'ip:unknown'),
    ('2001:db8:1:2::1', 'ip6:2001:db8:1:2::/64'),
    ('2001:db8:1:2:ffff::9', 'ip6:2001:db8:1:2::/64'),               # same /64, same bucket
    ('::ffff:203.0.113.7', 'ip:203.0.113.7'),
])
def test_client_key_on_vercel(monkeypatch, value, key):
    from app.ratelimit import client_key
    monkeypatch.setenv('VERCEL', '1')
    # the direct connection on vercel is vercel's own proxy, so it never counts
    assert client_key(_request([('x-real-ip', value), ('x-forwarded-for', '9.9.9.9')])) == key


def test_blocked_requests_never_reach_the_planner(env, monkeypatch):
    client, planner, _, _ = env
    monkeypatch.setenv('VERCEL', '1')
    for _ in range(6):
        post(client, '203.0.113.7')
    assert len(planner.calls) == 3
    from app.casework import get_casework_store
    assert len(get_casework_store().queue()) == 3


def test_rate_limited_is_logged_once_per_bucket_per_window(env, monkeypatch):
    client, _, clock, _ = env
    monkeypatch.setenv('VERCEL', '1')
    for _ in range(6):
        post(client, '203.0.113.7')
    [e] = events('rate_limited')
    assert (e['client'], e['limit'], e['max_requests']) == ('ip:203.0.113.7', 'ip', 3)
    clock[0] += 60
    for _ in range(5):
        post(client, '203.0.113.7')
    assert len(events('rate_limited')) == 2


def test_old_counters_are_cleaned_up_when_a_new_minute_starts(env):
    client, _, clock, ratelimit = env
    store = ratelimit.get_rate_store()
    store.hit('ip:203.0.113.7', T0 - 7200)                           # minute row from 2 hours ago
    store.hit('global:day', DAY - 3 * 86400)                         # day row from 3 days ago
    store.hit('global:day', DAY - 86400)                             # yesterday, kept
    post(client)
    rows = {r[0:2] for r in store.conn.execute('SELECT bucket, window_start FROM rate_counters').fetchall()}
    assert ('ip:203.0.113.7', T0 - 7200) not in rows
    assert ('global:day', DAY - 3 * 86400) not in rows
    assert ('global:day', DAY - 86400) in rows


def test_store_down_fails_closed(env, monkeypatch):
    client, planner, _, ratelimit = env

    class Broken:
        def hit(self, *a):
            raise sqlite3.OperationalError('database is locked')

    monkeypatch.setattr(ratelimit, 'get_rate_store', lambda: Broken())
    r = post(client)
    assert r.status_code == 503 and r.json() == {'detail': 'try again later'}
    assert planner.calls == []
    assert events('rate_limit_unavailable')[0]['error'] == 'OperationalError'
