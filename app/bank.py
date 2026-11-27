"""mock bank (Sargis). accounts with balances and an append-only ledger. no real money anywhere.

the only caller is meant to be Blake's LimitControl, through its bank= hook. it calls
bank(idempotency_key=, customer_id=, transaction_id=, amount_cents=): returning means settled, raising means
unknown, and limit control keeps the refund reserved and escalates it. nothing else should import this. no
agent, no route, no orchestrator. tests/test_bank.py checks the imports so that stays true.

TODO(Blake): to switch it on, gate._controls() builds limit control with the bank, the rest is already
wired on your side:
    from app.bank import MockBank
    lc = LimitControl(store, bank=MockBank(is_revoked=lambda: lc.is_revoked()))
the lambda reads lc when the bank calls it, not when it's built, so referring to lc on the same line is fine.
also, admin-approved escalations insert 'settled' without calling the bank, so they never pay out.
I'll send you the details.

lives in the same database as the casework store: neon on vercel, casework.db next to the control store locally.
"""
import re
import sqlite3
import threading
import time
import uuid

from app.casework.store import db_path
from app.controls.limits import MAX_AMOUNT_CENTS
from app.controls.pg import PgConn, is_pg_url
from app.controls.store import SEED_CUSTOMERS
from app.monitoring.audit import log_event

OPENING_BALANCE_CENTS = 100_000          # $1,000.00 for every synthetic customer

_CUSTOMER = re.compile(r'C-[0-9]{1,9}')
_TXN = re.compile(r'T-[0-9]{1,9}')
_MAX_KEY = 100

_TABLES = """
CREATE TABLE IF NOT EXISTS bank_accounts(
  customer_id TEXT PRIMARY KEY, balance_cents BIGINT NOT NULL CHECK(balance_cents >= 0), opened_us BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS bank_ledger(
  entry_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, customer_id TEXT NOT NULL, transaction_id TEXT,
  kind TEXT NOT NULL CHECK(kind IN ('opening','refund_credit')),
  amount_cents BIGINT NOT NULL CHECK(amount_cents > 0), balance_after_cents BIGINT NOT NULL, at_us BIGINT NOT NULL);
"""

SCHEMA = _TABLES + """
CREATE TRIGGER IF NOT EXISTS bank_ledger_no_update BEFORE UPDATE ON bank_ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS bank_ledger_no_delete BEFORE DELETE ON bank_ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
"""

PG_SCHEMA = _TABLES + """
CREATE OR REPLACE FUNCTION bank_ledger_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'ledger is append-only'; END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS bank_ledger_append_only ON bank_ledger;
CREATE TRIGGER bank_ledger_append_only BEFORE UPDATE OR DELETE ON bank_ledger
  FOR EACH ROW EXECUTE FUNCTION bank_ledger_append_only();
"""

_CREDIT = 'UPDATE bank_accounts SET balance_cents = balance_cents + ? WHERE customer_id = ? RETURNING balance_cents'
_LEDGER = ('INSERT INTO bank_ledger(entry_id, idempotency_key, customer_id, transaction_id, kind, amount_cents, '
           'balance_after_cents, at_us) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(idempotency_key) DO NOTHING')


class BankError(Exception):
    """anything the bank raises. limit control treats every one of them as settlement unknown."""


class BankRejected(BankError):
    """bad input, unknown customer, or a reused key with different details. nothing was credited."""


class BankRefused(BankError):
    """the kill switch was on (or couldn't be read) when the credit was about to commit. nothing was credited."""


def _now_us():
    return time.time_ns() // 1000


class MockBank:
    def __init__(self, path=None, *, is_revoked=None):
        self.path = path or db_path()
        self.pg = is_pg_url(self.path)
        self._is_revoked = is_revoked
        self.lock = threading.RLock()
        if self.pg:
            self.conn = PgConn(self.path)
            self.conn.execute_script(PG_SCHEMA)
        else:
            self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=10)
            if self.path != ':memory:':
                self.conn.execute('PRAGMA journal_mode = WAL')
            self.conn.executescript(SCHEMA)
        self._seed()

    # -------------------------------------------------------------- plumbing
    def _begin(self):
        # postgres gets a plain BEGIN on purpose. PgConn turns BEGIN IMMEDIATE into Blake's global control-store
        # lock, and the bank has no business holding that. the row lock from the balance UPDATE is enough here
        self.conn.execute('BEGIN' if self.pg else 'BEGIN IMMEDIATE')

    def _rollback(self):
        try:
            if self.conn.in_transaction:
                self.conn.execute('ROLLBACK')
        except Exception:
            pass

    def _seed(self):
        """opening balance for every customer limit control knows. it's in the ledger too, so ledger sums match balances."""
        with self.lock:
            for customer_id, *_ in SEED_CUSTOMERS:
                now = _now_us()
                self._begin()
                try:
                    added = self.conn.execute(
                        'INSERT INTO bank_accounts(customer_id, balance_cents, opened_us) VALUES (?,?,?) '
                        'ON CONFLICT DO NOTHING', (customer_id, OPENING_BALANCE_CENTS, now)).rowcount
                    if added == 1:
                        self.conn.execute(_LEDGER, ('L-' + uuid.uuid4().hex, 'opening:' + customer_id, customer_id,
                                                    None, 'opening', OPENING_BALANCE_CENTS, OPENING_BALANCE_CENTS, now))
                    self.conn.execute('COMMIT')
                except BaseException:
                    self._rollback()
                    raise

    def _reject(self, why, **fields):
        log_event('bank', 'bank_credit_rejected', severity='medium', reason=why, **fields)
        raise BankRejected(why)

    def _revoked(self):
        if self._is_revoked is None:
            return False
        try:
            return bool(self._is_revoked())
        except Exception:                 # can't tell, so treat it as revoked
            return True

    # -------------------------------------------------------------- the one way money moves
    def __call__(self, *, idempotency_key, customer_id, transaction_id, amount_cents):
        """credit a refund. returns {'entry_id', 'balance_after_cents', 'replayed'} or raises BankError."""
        shown = {'idempotency_key': str(idempotency_key)[:_MAX_KEY], 'customer_id': str(customer_id)[:20],
                 'transaction_id': str(transaction_id)[:20]}
        # limit control checks all of this already. the bank checks again because it's the last stop before money
        if not (isinstance(idempotency_key, str) and 0 < len(idempotency_key) <= _MAX_KEY and idempotency_key.isprintable()):
            self._reject('bad idempotency key', **shown)
        if not (isinstance(customer_id, str) and _CUSTOMER.fullmatch(customer_id)):
            self._reject('bad customer id', **shown)
        if not (isinstance(transaction_id, str) and _TXN.fullmatch(transaction_id)):
            self._reject('bad transaction id', **shown)
        if type(amount_cents) is not int or not 0 < amount_cents <= MAX_AMOUNT_CENTS:      # bool is out too
            self._reject('bad amount', amount=repr(amount_cents)[:40], **shown)

        with self.lock:
            now = _now_us()
            entry_id = 'L-' + uuid.uuid4().hex
            self._begin()
            try:
                # credit first: on postgres this also locks the account row, so a second credit for the
                # same key waits here and then trips over the unique key below
                # fetchall, not fetchone: sqlite won't COMMIT while a RETURNING statement is half read
                rows = self.conn.execute(_CREDIT, (amount_cents, customer_id)).fetchall()
                row = rows[0] if rows else None
                if row is None:
                    self._rollback()
                    self._reject('unknown customer', **shown)
                balance = row[0]
                added = self.conn.execute(_LEDGER, (entry_id, idempotency_key, customer_id, transaction_id,
                                                    'refund_credit', amount_cents, balance, now)).rowcount
                if added != 1:
                    self._rollback()      # undoes the credit above
                    return self._replay(idempotency_key, customer_id, transaction_id, amount_cents, shown)
                # last check right before the money is final, in case the switch flipped after limit control looked
                if self._revoked():
                    self._rollback()
                    log_event('bank', 'bank_credit_refused', severity='high', reason='authority revoked',
                              amount_cents=amount_cents, **shown)
                    raise BankRefused('authority revoked')
                self.conn.execute('COMMIT')
            except BankError:
                raise
            except BaseException:
                self._rollback()
                raise
        log_event('bank', 'bank_credit', entry_id=entry_id, amount_cents=amount_cents, balance_after_cents=balance,
                  **shown)
        return {'entry_id': entry_id, 'balance_after_cents': balance, 'replayed': False}

    def _replay(self, idempotency_key, customer_id, transaction_id, amount_cents, shown):
        """same key again. same details means it already went through, so report that and pay nothing.
        different details means someone reused a key, which is never fine."""
        prev = self.conn.execute('SELECT entry_id, customer_id, transaction_id, kind, amount_cents, balance_after_cents '
                                 'FROM bank_ledger WHERE idempotency_key = ?', (idempotency_key,)).fetchall()
        prev = prev[0] if prev else None
        if prev is None or prev[1:5] != (customer_id, transaction_id, 'refund_credit', amount_cents):
            self._reject('idempotency key reused with different details', amount_cents=amount_cents, **shown)
        log_event('bank', 'bank_credit_replayed', entry_id=prev[0], amount_cents=amount_cents, **shown)
        return {'entry_id': prev[0], 'balance_after_cents': prev[5], 'replayed': True}

    # -------------------------------------------------------------- reads
    def balance_cents(self, customer_id):
        with self.lock:
            row = self.conn.execute('SELECT balance_cents FROM bank_accounts WHERE customer_id = ?',
                                    (customer_id,)).fetchone()
        return None if row is None else row[0]

    def ledger(self, customer_id=None):
        sql = ('SELECT entry_id, idempotency_key, customer_id, transaction_id, kind, amount_cents, balance_after_cents, '
               'at_us FROM bank_ledger')
        with self.lock:
            cur = (self.conn.execute(sql + ' WHERE customer_id = ? ORDER BY at_us', (customer_id,)) if customer_id
                   else self.conn.execute(sql + ' ORDER BY at_us'))
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def close(self):
        with self.lock:
            self.conn.close()
