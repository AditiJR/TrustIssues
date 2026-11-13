"""Durable control store (SQLite, stdlib). Ledger, refunds, escalations, cases, authority flag, audit."""
import contextlib
import hashlib
import json
import sqlite3
import sys
import threading
from datetime import datetime, timezone

from app.controls.limits import PER_TXN_LIMIT_CENTS, WEEKLY_LIMIT_CENTS, WINDOW_US

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS customers(
  customer_id TEXT PRIMARY KEY, email TEXT NOT NULL, account_last4 TEXT NOT NULL, account_no TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(
  transaction_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents > 0));
CREATE TABLE IF NOT EXISTS cases(
  case_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL, customer_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','closed')), opened_us INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS refunds(
  decision_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, customer_id TEXT NOT NULL,
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0), at_us INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('reserved','settled','void')),
  authority TEXT NOT NULL CHECK(authority IN ('agent','admin')),
  CHECK(authority = 'admin' OR amount_cents <= {PER_TXN_LIMIT_CENTS}));
CREATE UNIQUE INDEX IF NOT EXISTS one_active_refund_per_txn ON refunds(transaction_id) WHERE status != 'void';
CREATE TRIGGER IF NOT EXISTS weekly_cap BEFORE INSERT ON refunds
WHEN (SELECT COALESCE(SUM(amount_cents),0) FROM refunds
      WHERE status != 'void' AND at_us >= NEW.at_us - {WINDOW_US}) + NEW.amount_cents > {WEEKLY_LIMIT_CENTS}
BEGIN SELECT RAISE(ABORT, 'weekly cap'); END;
CREATE TABLE IF NOT EXISTS escalations(
  escalation_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, customer_id TEXT NOT NULL,
  amount_cents INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','admin_approved','admin_denied')),
  opened_us INTEGER NOT NULL, decided_us INTEGER, decided_by TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS one_escalation_per_txn ON escalations(transaction_id);
CREATE TABLE IF NOT EXISTS authority_state(
  id INTEGER PRIMARY KEY CHECK(id = 1), revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
  changed_us INTEGER, changed_by TEXT, reason TEXT);
INSERT OR IGNORE INTO authority_state(id, revoked) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at_us INTEGER NOT NULL, kind TEXT NOT NULL, decision_id TEXT NOT NULL,
  actor TEXT NOT NULL, body TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
"""

def safe_repr(value, limit=200):
    """repr() that cannot raise and is always storable: bounded, valid UTF-8."""
    try:
        text = repr(value)
    except Exception:
        text = '<unrepresentable %s>' % type(value).__name__
    return text.encode('utf-8', 'replace').decode('utf-8')[:limit]


def clean_text(value, limit=200):
    """Free text made safe to store, hash and send back: a str, valid UTF-8, bounded."""
    if not isinstance(value, str):
        return safe_repr(value, limit)
    return value.encode('utf-8', 'replace').decode('utf-8')[:limit]


def storable(value):
    """True for a str SQLite can bind (no lone surrogates)."""
    if not isinstance(value, str):
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def token_digest(token):
    """sha256 of a scope token. Only the digest is stored, so a copy of the database cannot be replayed as a scope."""
    if not isinstance(token, str):
        return None
    return hashlib.sha256(token.encode('utf-8', 'replace')).hexdigest()


# Synthetic data only. IDs, owners and amounts match the red team's fixtures.
SEED_CUSTOMERS = [
    ('C-1', 'c1.customer@shop.example.test', '4401', '000111222333'),
    ('C-2', 'c2.customer@shop.example.test', '7702', '000444555666'),
]
SEED_TRANSACTIONS = [('T-1001', 'C-1', 25000), ('T-1002', 'C-1', 8000), ('T-1003', 'C-2', 9000)] + \
                    [(f'T-{n}', 'C-1', 10000) for n in range(1004, 1010)]


class Store:
    """One connection, one process lock. Cross-process safety comes from BEGIN IMMEDIATE."""

    def __init__(self, path=':memory:', seed=True, busy_timeout=10):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=busy_timeout)
        self.conn.execute('PRAGMA foreign_keys = ON')
        if path != ':memory:':
            self.conn.execute('PRAGMA journal_mode = WAL')
            self.conn.execute('PRAGMA synchronous = FULL')
        with self.lock:
            self.conn.executescript(SCHEMA)
            if seed:
                self.conn.executemany('INSERT OR IGNORE INTO customers VALUES (?,?,?,?)', SEED_CUSTOMERS)
                self.conn.executemany('INSERT OR IGNORE INTO transactions VALUES (?,?,?)', SEED_TRANSACTIONS)

    def begin(self):
        if self.conn.in_transaction:            # an abandoned transaction is rolled back, never built upon
            self.conn.execute('ROLLBACK')
        self.conn.execute('BEGIN IMMEDIATE')

    def commit(self):
        self.conn.execute('COMMIT')

    def rollback(self):
        try:
            if self.conn.in_transaction:
                self.conn.execute('ROLLBACK')
        except sqlite3.Error:
            pass

    @contextlib.contextmanager
    def tx(self):
        """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK on any error. Caller holds self.lock."""
        self.begin()
        try:
            yield
            self.conn.execute('COMMIT')
        except BaseException:
            self.rollback()
            raise

    def fallback_audit(self, kind, decision_id, actor, body):
        """Last resort when the audit table cannot be written: one JSON line in <db>.audit-fallback.jsonl
        (stderr for an in-memory store). Never raises."""
        try:
            line = json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'kind': kind, 'decision_id': decision_id,
                               'actor': actor, **body}, sort_keys=True, default=str)
            if self.path == ':memory:':
                print('AUDIT-FALLBACK ' + line, file=sys.stderr)
            else:
                with open(self.path + '.audit-fallback.jsonl', 'a') as fh:
                    fh.write(line + '\n')
        except Exception:
            pass

    def one(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()

    def all(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def append_audit(self, at_us, kind, decision_id, actor, body):
        """Must be called inside a transaction. body is a JSON-serialisable dict of plain values."""
        text = json.dumps(body, sort_keys=True, ensure_ascii=True)
        prev = self.one('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1')
        prev_hash = prev[0] if prev else '0' * 64
        h = hashlib.sha256('|'.join([prev_hash, str(at_us), kind, decision_id, actor, text]).encode()).hexdigest()
        self.conn.execute('INSERT INTO audit(at_us, kind, decision_id, actor, body, prev_hash, hash) VALUES (?,?,?,?,?,?,?)',
                          (at_us, kind, decision_id, actor, text, prev_hash, h))

    def read_audit(self, kinds=None):
        with self.lock:
            rows = self.all('SELECT seq, at_us, kind, decision_id, actor, body FROM audit ORDER BY seq')
        out = []
        for seq, at_us, kind, did, actor, body in rows:
            if kinds and kind not in kinds:
                continue
            try:
                fields = json.loads(body)
                if not isinstance(fields, dict):
                    raise ValueError
            except ValueError:
                fields = {'unparseable_body': True}
            out.append({**fields, 'seq': seq, 'at_us': at_us, 'kind': kind, 'decision_id': did, 'actor': actor})
        return out

    def verify_audit_chain(self):
        """True if every row still hashes to its stored value and links to the row before it. This detects an
        edited, removed or reordered row in the middle of the log. It cannot detect rows cut from the end, or a
        log rewritten from scratch by someone who can write the file: compare the latest hash with a copy kept
        elsewhere (each retest evidence file records it) for that."""
        with self.lock:
            rows = self.all('SELECT at_us, kind, decision_id, actor, body, prev_hash, hash FROM audit ORDER BY seq')
        prev = '0' * 64
        for at_us, kind, did, actor, body, prev_hash, h in rows:
            want = hashlib.sha256('|'.join([prev, str(at_us), kind, did, actor, body]).encode()).hexdigest()
            if prev_hash != prev or h != want:
                return False
            prev = h
        return True

    def audit_head(self):
        """Hash of the latest audit row. Record it somewhere else to anchor the chain."""
        with self.lock:
            row = self.one('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1')
        return row[0] if row else '0' * 64
