"""case queue, mock mailbox and decision records. sqlite locally, postgres when given a postgres:// url.

same idea as the control store (app/controls/store.py), and it reuses Blake's PgConn for postgres.
every write is one INSERT or UPDATE in autocommit, so none of it needs his write lock.
nothing in here sends real email, the mailbox is just a table.
"""
import os
import sqlite3
import threading
import time
import uuid

from app.controls.pg import PgConn, is_pg_url

OUTCOMES = ('approved', 'escalated', 'denied')
EMAIL_KINDS = ('acknowledgement', 'decision')

_TABLES = """
CREATE TABLE IF NOT EXISTS case_queue(
  case_id TEXT PRIMARY KEY, scope_case_id TEXT NOT NULL, customer_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0), reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','decided')), queued_us BIGINT NOT NULL, updated_us BIGINT);
CREATE TABLE IF NOT EXISTS mailbox(
  message_id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('acknowledgement','decision')),
  to_addr TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, created_us BIGINT NOT NULL,
  UNIQUE(case_id, kind));
CREATE TABLE IF NOT EXISTS decision_records(
  case_id TEXT PRIMARY KEY, decision_id TEXT,
  outcome TEXT NOT NULL CHECK(outcome IN ('approved','escalated','denied')),
  reason TEXT NOT NULL, rule TEXT, recorded_us BIGINT NOT NULL);
"""

# sent mail and decision records are history, so nobody gets to rewrite them
SCHEMA = _TABLES + """
CREATE TRIGGER IF NOT EXISTS mailbox_no_update BEFORE UPDATE ON mailbox BEGIN SELECT RAISE(ABORT, 'mailbox is append-only'); END;
CREATE TRIGGER IF NOT EXISTS mailbox_no_delete BEFORE DELETE ON mailbox BEGIN SELECT RAISE(ABORT, 'mailbox is append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_no_update BEFORE UPDATE ON decision_records BEGIN SELECT RAISE(ABORT, 'decision records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_no_delete BEFORE DELETE ON decision_records BEGIN SELECT RAISE(ABORT, 'decision records are append-only'); END;
"""

PG_SCHEMA = _TABLES + """
CREATE OR REPLACE FUNCTION casework_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS mailbox_append_only ON mailbox;
CREATE TRIGGER mailbox_append_only BEFORE UPDATE OR DELETE ON mailbox FOR EACH ROW EXECUTE FUNCTION casework_append_only();
DROP TRIGGER IF EXISTS decisions_append_only ON decision_records;
CREATE TRIGGER decisions_append_only BEFORE UPDATE OR DELETE ON decision_records
  FOR EACH ROW EXECUTE FUNCTION casework_append_only();
"""

DEFAULT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'casework.db'))


def db_path():
    """TRUSTISSUES_CASEWORK_DB, else next to the control store, else DATABASE_URL, else logs/casework.db.

    following the control store means tests that point it at a temp dir don't write to logs/ by accident,
    and on vercel both end up in the same neon database."""
    explicit = os.environ.get('TRUSTISSUES_CASEWORK_DB')
    if explicit:
        return explicit
    control = os.environ.get('TRUSTISSUES_CONTROL_DB')
    if control:
        if is_pg_url(control) or control == ':memory:':
            return control
        return os.path.join(os.path.dirname(os.path.abspath(control)), 'casework.db')
    return os.environ.get('DATABASE_URL') or DEFAULT_PATH


def _now_us():
    return time.time_ns() // 1000


class CaseworkStore:
    def __init__(self, path=':memory:'):
        self.path = path
        self.pg = is_pg_url(path)
        self.lock = threading.RLock()
        if self.pg:
            self.conn = PgConn(path)
            self.conn.execute_script(PG_SCHEMA)
            return
        if path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        if path != ':memory:':
            self.conn.execute('PRAGMA journal_mode = WAL')
        self.conn.executescript(SCHEMA)

    def _write(self, sql, args):
        """one statement, autocommit. returns how many rows it touched."""
        with self.lock:
            return self.conn.execute(sql, args).rowcount

    def _rows(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    # -- writes. all of them are safe to repeat: a second call for the same case does nothing
    def enqueue(self, case_id, scope_case_id, customer_id, transaction_id, amount_cents, reason):
        """True if the case was added, False if it was already in the queue."""
        return self._write(
            "INSERT INTO case_queue(case_id, scope_case_id, customer_id, transaction_id, amount_cents, reason, status, "
            "queued_us) VALUES (?,?,?,?,?,?, 'queued', ?) ON CONFLICT DO NOTHING",
            (case_id, scope_case_id, customer_id, transaction_id, amount_cents, reason, _now_us())) == 1

    def save_email(self, case_id, kind, to_addr, subject, body):
        """message id, or None if this case already has an email of this kind."""
        message_id = 'M-' + uuid.uuid4().hex
        added = self._write(
            'INSERT INTO mailbox(message_id, case_id, kind, to_addr, subject, body, created_us) '
            'VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
            (message_id, case_id, kind, to_addr, subject, body, _now_us()))
        return message_id if added == 1 else None

    def record_decision(self, case_id, decision_id, outcome, reason, rule):
        """True if recorded, False if this case already has a record. also marks the queue entry decided."""
        now = _now_us()
        added = self._write(
            'INSERT INTO decision_records(case_id, decision_id, outcome, reason, rule, recorded_us) '
            'VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING', (case_id, decision_id, outcome, reason, rule, now)) == 1
        if added:
            self._write("UPDATE case_queue SET status = 'decided', updated_us = ? WHERE case_id = ?", (now, case_id))
        return added

    # -- reads, for tests and later for the admin side
    def queue(self, case_id=None):
        if case_id is None:
            return self._rows('SELECT * FROM case_queue ORDER BY queued_us')
        return self._rows('SELECT * FROM case_queue WHERE case_id = ?', (case_id,))

    def mailbox(self, case_id=None):
        if case_id is None:
            return self._rows('SELECT * FROM mailbox ORDER BY created_us')
        return self._rows('SELECT * FROM mailbox WHERE case_id = ? ORDER BY created_us', (case_id,))

    def decisions(self, case_id=None):
        if case_id is None:
            return self._rows('SELECT * FROM decision_records ORDER BY recorded_us')
        return self._rows('SELECT * FROM decision_records WHERE case_id = ?', (case_id,))

    def close(self):
        with self.lock:
            self.conn.close()
