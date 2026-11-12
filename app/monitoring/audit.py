"""Shared audit log for every component.

Extends the starter's logs/events.jsonl instead of replacing it: same file, same one JSON object
per line, same 'timestamp', 'actor' and 'action' keys, so GET /logs and run_demo.py keep working.
What it adds:

  seq, event_id     a running number and a unique id for every entry
  severity          info | low | medium | high | critical
  case_id, decision_id   so an investigator can pull every event for one case or decision
  prev_hash, hash   sha256 chain. Editing, deleting or reordering a line breaks verify().
  redaction         full account numbers, secrets and email local parts are masked before
                    anything is written, so the log itself cannot leak them (RT-19)

json.dumps escapes newlines, so customer text cannot start a new, forged line (RT-18).

Usage from any component:

    from app.monitoring.audit import log_event
    log_event('orchestrator', 'step_start', case_id=case_id, step=1, agent='records')

The file is TRUSTISSUES_EVENT_LOG if set, otherwise <repo>/logs/events.jsonl.
"""
import fcntl
import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone

SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
GENESIS = '0' * 64
MAX_STR = 2000

DEFAULT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'events.jsonl'))

# ------------------------------------------------------------------ redaction
# 9 to 19 digits, optionally split by spaces or dashes: bank account and card number lengths.
# Shorter runs (amounts, last4, ids like T-1001) are kept because investigators need them.
_ACCOUNT = re.compile(r'(?<![\w-])(?:\d[ -]?){8,18}\d(?![\w-])')
_EMAIL = re.compile(r'\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
_SECRET_KEYS = ('secret', 'token', 'password', 'api_key', 'apikey', 'authorization', 'account_no')
_RESERVED = {'timestamp', 'seq', 'event_id', 'actor', 'action', 'severity', 'prev_hash', 'hash'}


def _mask_account(match):
    digits = re.sub(r'\D', '', match.group(0))
    return '<ACCT ***%s>' % digits[-4:]


def redact_text(text):
    """Mask account-length digit runs (keep last 4) and email local parts (keep first letter and domain)."""
    text = _ACCOUNT.sub(_mask_account, text)
    return _EMAIL.sub(lambda m: '%s***@%s' % (m.group(1), m.group(2)), text)


def redact(value, _key=''):
    """Recursively redact a JSON-like value. Keys that look like secrets are replaced outright."""
    if any(s in _key.lower() for s in _SECRET_KEYS):
        return '<REDACTED>'
    if isinstance(value, str):
        out = redact_text(value)
        return out if len(out) <= MAX_STR else out[:MAX_STR] + '...<truncated>'
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact(v, _key) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value), _key)


def _entry_hash(prev_hash, entry):
    body = {k: v for k, v in entry.items() if k not in ('prev_hash', 'hash')}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    return hashlib.sha256((prev_hash + '|' + canonical).encode('ascii')).hexdigest()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    """Append-only JSONL log with a hash chain. Safe across threads (lock) and processes (flock)."""

    def __init__(self, path=None):
        self.path = os.path.abspath(path or os.environ.get('TRUSTISSUES_EVENT_LOG') or DEFAULT_PATH)
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    # -------------------------------------------------------------- writing
    def _tail(self, fh):
        """(seq, hash) of the last chained line in the file, read from the end."""
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block, data = 8192, b''
        pos = size
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
            lines = [ln for ln in data.split(b'\n') if ln.strip()]
            # need at least one complete line (or the whole file) to decide
            for raw in reversed(lines if pos == 0 else lines[1:]):
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(obj, dict) and 'hash' in obj and 'seq' in obj:
                    return int(obj['seq']), obj['hash']
            if pos == 0:
                break
        return 0, GENESIS

    def log(self, actor, action, *, severity='info', case_id=None, decision_id=None, **fields):
        """Write one event and return it (already redacted). Never raises: logging must not break a request."""
        if severity not in SEVERITY_RANK:
            severity = 'info'
        extra = {k: v for k, v in fields.items() if k not in _RESERVED}
        entry = {
            'timestamp': _now_iso(),
            'event_id': 'EV-' + uuid.uuid4().hex[:16],
            'actor': redact(str(actor))[:60],
            'action': redact(str(action))[:80],
            'severity': severity,
        }
        if case_id is not None:
            entry['case_id'] = redact(str(case_id))[:80]
        if decision_id is not None:
            entry['decision_id'] = redact(str(decision_id))[:80]
        entry.update(redact(extra))
        try:
            with self._lock, open(self.path, 'a+b') as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    seq, prev = self._tail(fh)
                    entry['seq'] = seq + 1
                    entry['prev_hash'] = prev
                    entry['hash'] = _entry_hash(prev, entry)
                    fh.seek(0, os.SEEK_END)
                    fh.write((json.dumps(entry, ensure_ascii=True, default=str) + '\n').encode('ascii'))
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError as exc:
            entry['write_error'] = type(exc).__name__
        return entry

    # -------------------------------------------------------------- reading
    def read(self, *, action=None, actor=None, case_id=None, min_severity=None, since=None, limit=None):
        """Events oldest first, optionally filtered. action may be a string or a collection of strings."""
        if not os.path.exists(self.path):
            return []
        actions = {action} if isinstance(action, str) else (set(action) if action else None)
        floor = SEVERITY_RANK.get(min_severity, 0)
        out = []
        with open(self.path, 'rb') as fh:
            for raw in fh:
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(e, dict):
                    continue
                if actions and e.get('action') not in actions:
                    continue
                if actor and e.get('actor') != actor:
                    continue
                if case_id and e.get('case_id') != case_id:
                    continue
                if SEVERITY_RANK.get(e.get('severity', 'info'), 0) < floor:
                    continue
                if since and str(e.get('timestamp', '')) < since:
                    continue
                out.append(e)
        return out[-limit:] if limit else out

    def verify(self):
        """Check the hash chain.

        Lines written by the original starter code have no hash. They are allowed only before the
        first chained line. Returns ok plus where the first problem is, so an investigator can look."""
        report = {'ok': True, 'entries': 0, 'chained': 0, 'legacy_unchained': 0, 'problem': None, 'line': None,
                  'head': GENESIS}
        if not os.path.exists(self.path):
            return report
        prev, expected_seq = GENESIS, 1
        with open(self.path, 'rb') as fh:
            for lineno, raw in enumerate(fh, 1):
                if not raw.strip():
                    continue
                report['entries'] += 1
                try:
                    e = json.loads(raw)
                except ValueError:
                    return {**report, 'ok': False, 'problem': 'unparseable line', 'line': lineno}
                if 'hash' not in e:
                    if report['chained']:
                        return {**report, 'ok': False, 'problem': 'unchained line after chain start', 'line': lineno}
                    report['legacy_unchained'] += 1
                    continue
                if e.get('prev_hash') != prev:
                    return {**report, 'ok': False, 'problem': 'broken link (line removed, inserted or reordered)',
                            'line': lineno}
                if e.get('seq') != expected_seq:
                    return {**report, 'ok': False, 'problem': 'sequence gap', 'line': lineno}
                if _entry_hash(prev, e) != e.get('hash'):
                    return {**report, 'ok': False, 'problem': 'content changed after it was written', 'line': lineno}
                prev, expected_seq = e['hash'], expected_seq + 1
                report['chained'] += 1
        report['head'] = prev
        return report


# ------------------------------------------------------------------ module-level default
_default = None
_default_lock = threading.Lock()


def get_audit_log():
    """The process-wide log. Re-created if TRUSTISSUES_EVENT_LOG changes (tests rely on that)."""
    global _default
    want = os.path.abspath(os.environ.get('TRUSTISSUES_EVENT_LOG') or DEFAULT_PATH)
    with _default_lock:
        if _default is None or _default.path != want:
            _default = AuditLog(want)
        return _default


def log_event(actor, action, **fields):
    """Shortcut for get_audit_log().log(...). Use this from every component."""
    return get_audit_log().log(actor, action, **fields)
