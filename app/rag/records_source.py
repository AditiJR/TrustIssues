"""Where customer and transaction records come from.

Team decision: Blake's control database is the single source of truth for customers and
transactions. Ownership checks, refund limits and access control all run against it, so the
Records agent must see exactly the same rows.

  ControlDBSource  reads Blake's SQLite file (TRUSTISSUES_CONTROL_DB, default logs/controls.db).
                   The connection is query-only, and it never selects account_no: full account
                   numbers stay inside Blake's controls and mock bank.
  LocalSource      this store's own tables, seeded from app/rag/seed/customers.json. Used only
                   until Blake's branch is merged, so this branch still runs on its own.

pick_source() chooses: TRUSTISSUES_RECORDS_SOURCE=control or local forces one. The default (auto)
uses Blake's database when his code is present or his database file exists, otherwise LocalSource.
"""
import os
import sqlite3
import threading

DEFAULT_CONTROL_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'controls.db'))


def control_db_path():
    """Same rule as Blake's gate.db_path()."""
    try:
        from app.controls.gate import db_path      # present once Blake's branch is merged
        return os.path.abspath(db_path())
    except ImportError:
        return os.path.abspath(os.environ.get('TRUSTISSUES_CONTROL_DB') or DEFAULT_CONTROL_DB)


def _blake_code_present():
    try:
        import app.controls.gate  # noqa: F401
        return True
    except ImportError:
        return False


class ControlDBSource:
    """Read-only view of Blake's customers and transactions tables."""
    name = 'control'
    writable = False

    def __init__(self, path=None):
        self.path = os.path.abspath(path or control_db_path())
        self._conn = None
        self._lock = threading.Lock()

    def _db(self):
        with self._lock:
            if self._conn is None:
                if not os.path.exists(self.path):
                    try:     # Blake's gate creates and seeds his store on first use
                        from app.controls import gate
                        gate.is_revoked()
                    except ImportError:
                        pass
                if not os.path.exists(self.path):
                    raise FileNotFoundError('control database not found at %s' % self.path)
                self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
                self._conn.execute('PRAGMA query_only = 1')     # this side never writes Blake's data
            return self._conn

    def get_customer(self, customer_id):
        row = self._db().execute('SELECT customer_id, email, account_last4 FROM customers WHERE customer_id = ?',
                                 (customer_id,)).fetchone()
        return {'customer_id': row[0], 'name': None, 'email': row[1], 'account_last4': row[2]} if row else None

    def get_transaction(self, transaction_id):
        row = self._db().execute('SELECT transaction_id, customer_id, amount_cents FROM transactions '
                                 'WHERE transaction_id = ?', (transaction_id,)).fetchone()
        return {'transaction_id': row[0], 'customer_id': row[1], 'amount_cents': row[2], 'purchased_on': None,
                'item': None} if row else None

    def transactions_for(self, customer_id):
        rows = self._db().execute('SELECT transaction_id, amount_cents FROM transactions WHERE customer_id = ? '
                                  'ORDER BY transaction_id', (customer_id,)).fetchall()
        return [{'transaction_id': r[0], 'amount_cents': r[1], 'purchased_on': None, 'item': None} for r in rows]

    def bank_account(self, customer_id):
        return None          # by design: payouts go through Blake's mock bank, not through this store


class LocalSource:
    """This store's own tables (standalone fallback)."""
    name = 'local'
    writable = True

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS customers(
      customer_id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, account_no TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS transactions(
      transaction_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(customer_id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents > 0), purchased_on TEXT NOT NULL, item TEXT NOT NULL);
    """

    def __init__(self, conn):
        self.conn = conn
        conn.executescript(self.SCHEMA)

    def raw_customer(self, customer_id):
        row = self.conn.execute('SELECT customer_id, name, email, account_no FROM customers WHERE customer_id = ?',
                                (customer_id,)).fetchone()
        return dict(zip(['customer_id', 'name', 'email', 'account_no'], row)) if row else None

    def get_customer(self, customer_id):
        p = self.raw_customer(customer_id)
        return {'customer_id': p['customer_id'], 'name': p['name'], 'email': p['email'],
                'account_last4': p['account_no'][-4:]} if p else None

    def get_transaction(self, transaction_id):
        row = self.conn.execute('SELECT transaction_id, customer_id, amount_cents, purchased_on, item FROM transactions '
                                'WHERE transaction_id = ?', (transaction_id,)).fetchone()
        return dict(zip(['transaction_id', 'customer_id', 'amount_cents', 'purchased_on', 'item'], row)) if row else None

    def transactions_for(self, customer_id):
        rows = self.conn.execute('SELECT transaction_id, amount_cents, purchased_on, item FROM transactions '
                                 'WHERE customer_id = ? ORDER BY transaction_id', (customer_id,)).fetchall()
        return [dict(zip(['transaction_id', 'amount_cents', 'purchased_on', 'item'], r)) for r in rows]

    def bank_account(self, customer_id):
        p = self.raw_customer(customer_id)
        return p['account_no'] if p else None


def pick_source(conn):
    mode = (os.environ.get('TRUSTISSUES_RECORDS_SOURCE') or 'auto').lower()
    if mode == 'local':
        return LocalSource(conn)
    if mode == 'control' or _blake_code_present() or os.path.exists(control_db_path()):
        return ControlDBSource()
    return LocalSource(conn)
