"""Postgres backend for the control store, behind the same small surface sqlite3 gave Store.

Why it exists: on a serverless host (Vercel) the local disk is wiped between requests, so the ledger, the
kill switch and the audit chain have to live in a hosted database. Store picks this when the path it is
given is a postgres:// URL. SQLite stays the default for tests and local runs.

What it keeps identical to SQLite, because the controls depend on it:
  * BEGIN IMMEDIATE  ->  BEGIN + a transaction-scoped advisory lock, so every writer, in any process or
                         serverless instance, is serialised. The weekly-cap check and the insert that
                         spends it therefore cannot interleave across instances.
  * rowcount, fetchone, fetchall, in_transaction, ROLLBACK of an abandoned transaction.
SQL is written once, in SQLite's dialect with ? placeholders; only the placeholder is translated here.
"""
import threading

try:
    import psycopg
    from psycopg.pq import TransactionStatus
except ImportError:                                  # SQLite-only installs do not need the driver
    psycopg = None
    TransactionStatus = None

WRITE_LOCK_ID = 7305_2026_11        # arbitrary constant: one global write lock for the control tables
SCHEMA_LOCK_ID = 7305_2026_12       # serialises first-time schema creation across cold starts


def is_pg_url(path):
    return isinstance(path, str) and path.startswith(('postgres://', 'postgresql://'))


def translate(sql):
    """SQLite-dialect SQL -> psycopg: '?' becomes '%s' and a literal '%' is escaped."""
    return sql.replace('%', '%%').replace('?', '%s')


class PgConn:
    """Just enough of sqlite3.Connection for Store, LimitControl and AccessControl."""

    def __init__(self, url, *, connect_timeout=10, readonly=False):
        if psycopg is None:
            raise RuntimeError('DATABASE_URL is set but psycopg is not installed (pip install "psycopg[binary]")')
        self._url = url
        self._timeout = connect_timeout
        self._readonly = readonly
        self._lock = threading.RLock()
        self._c = None
        self._connect()

    def _connect(self):
        # autocommit: transactions are explicit (BEGIN ... COMMIT) exactly as with SQLite's isolation_level=None.
        # prepare_threshold=None: a pooled (PgBouncer) endpoint cannot keep prepared statements.
        self._c = psycopg.connect(self._url, autocommit=True, prepare_threshold=None,
                                  connect_timeout=self._timeout)
        if self._readonly:
            self._c.execute('SET default_transaction_read_only = on')

    @property
    def in_transaction(self):
        return self._c is not None and not self._c.closed and \
            self._c.info.transaction_status in (TransactionStatus.INTRANS, TransactionStatus.INERROR)

    def _ensure(self):
        """A serverless database may drop an idle connection. Reconnect, but never in the middle of a
        transaction: its locks and uncommitted rows died with the old connection."""
        if self._c is None or self._c.closed or self._c.info.transaction_status == TransactionStatus.UNKNOWN:
            self._connect()

    def _dead(self):
        return self._c is None or self._c.closed or self._c.info.transaction_status == TransactionStatus.UNKNOWN

    def _first_statement(self, run):
        """Run one statement that is safe to repeat (a SELECT, or BEGIN before anything was done) and, if the
        server had silently dropped the connection, reconnect and run it once more. Never used inside a
        transaction, and never for a write: a write that may have reached the server is not repeated."""
        try:
            return run()
        except psycopg.OperationalError:
            if self.in_transaction or not self._dead():
                raise
            self._connect()
            return run()

    def execute(self, sql, args=()):
        with self._lock:
            head = sql.strip().upper()
            if head == 'BEGIN IMMEDIATE':
                self._ensure()
                self._first_statement(lambda: self._c.execute('BEGIN'))
                self._c.execute('SELECT pg_advisory_xact_lock(%s)', (WRITE_LOCK_ID,))
                return None
            if head in ('COMMIT', 'ROLLBACK'):
                return self._c.execute(head)
            if not self.in_transaction:
                self._ensure()
            run = (lambda: self._c.execute(translate(sql), tuple(args))) if args else (lambda: self._c.execute(sql))
            if head.startswith('SELECT') and not self.in_transaction:
                return self._first_statement(run)
            return run()

    def executemany(self, sql, rows):
        with self._lock:
            self._ensure()
            with self._c.cursor() as cur:
                cur.executemany(translate(sql), [tuple(r) for r in rows])

    def execute_script(self, script):
        """Run a multi-statement script (no parameters) under the schema lock."""
        with self._lock:
            self._ensure()
            self._c.execute('SELECT pg_advisory_lock(%s)', (SCHEMA_LOCK_ID,))
            try:
                self._c.execute(script)
            finally:
                self._c.execute('SELECT pg_advisory_unlock(%s)', (SCHEMA_LOCK_ID,))

    def close(self):
        with self._lock:
            if self._c is not None and not self._c.closed:
                self._c.close()
