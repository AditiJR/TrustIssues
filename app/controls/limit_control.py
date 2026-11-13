"""Limit control: deterministic refund decisions, outside the LLM.

Every call to decide() ends in exactly one audited outcome: approved, escalated or denied.
Nothing here reads a limit from a request, a prompt, a policy document or the environment.
"""
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from app.controls.limits import MAX_AMOUNT_CENTS, PER_TXN_LIMIT_CENTS, SCOPE_TTL_US, WEEKLY_LIMIT_CENTS, WINDOW_US
from app.controls.store import clean_text, safe_repr, token_digest      # safe_repr is re-exported

_ID_RE = {'customer': re.compile(r'C-[0-9]{1,9}'), 'txn': re.compile(r'T-[0-9]{1,9}')}
_AMOUNT_RE = re.compile(r'[0-9]{1,7}(\.[0-9]{1,2})?')
_CENT = Decimal('0.01')
_MAX = Decimal(MAX_AMOUNT_CENTS) / 100
REASON_CODES = ('damaged', 'not_received', 'duplicate_charge')
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_amount_cents(amount):
    """Return integer cents, or None if the amount is not a plain positive money value."""
    if isinstance(amount, bool):
        return None
    if isinstance(amount, str):
        if len(amount) > 16 or not _AMOUNT_RE.fullmatch(amount):
            return None
        d = Decimal(amount)
    elif isinstance(amount, Decimal):
        if not amount.is_finite():
            return None
        d = amount
    elif isinstance(amount, int):
        if amount.bit_length() > 40:
            return None
        d = Decimal(amount)
    else:
        return None                      # float and everything else
    if not (Decimal(0) < d <= _MAX):     # bound first, so quantize cannot overflow
        return None
    q = d.quantize(_CENT)
    if q != d:
        return None
    return int(q * 100)


class AdminPrincipal:
    """Opaque admin identity. Only access_control.authenticate_admin mints one."""
    __slots__ = ('name', '_key')
    _MINT = object()

    def __init__(self, name, key):
        if key is not AdminPrincipal._MINT:
            raise PermissionError('AdminPrincipal cannot be constructed directly')
        self.name, self._key = name, key


def _is_admin(p):
    return type(p) is AdminPrincipal and getattr(p, '_key', None) is AdminPrincipal._MINT


class LimitControl:
    def __init__(self, store, *, now=None, bank=None, require_reason=True):
        self._store = store
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._bank = bank
        self._require_reason = require_reason
        # Set the moment a stop is requested in this process, before the store write, and cleared only by a
        # successful admin restore. A stop therefore holds here even if the store cannot record it.
        self._stopped = False

    # -- clock -----------------------------------------------------------
    def _now_us(self):
        t = self._now()
        if not isinstance(t, datetime) or t.tzinfo is None or t.utcoffset() is None:
            raise ValueError('clock must return a timezone-aware datetime')
        d = t - _EPOCH
        return (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds

    # -- read-only views ---------------------------------------------------
    def _stamp(self):
        """Clock reading for an audit row that must be written even if the clock is broken."""
        try:
            return self._now_us()
        except Exception:
            return self._store.one('SELECT COALESCE(MAX(at_us),0) FROM audit')[0]

    def _audit_or_fallback(self, kind, decision_id, actor, body):
        """Write one audit row in its own transaction; if the store refuses, use the fallback sink.
        Caller holds the store lock. Returns True if the row reached the audit table."""
        st = self._store
        try:
            with st.tx():
                st.append_audit(self._stamp(), kind, decision_id, actor, body)
            return True
        except Exception:
            st.fallback_audit(kind, decision_id, actor, body)
            return False

    def is_revoked(self):
        if self._stopped:
            return True
        with self._store.lock:
            try:
                row = self._store.one('SELECT revoked FROM authority_state WHERE id = 1')
            except sqlite3.Error:
                return True
            return row is None or row[0] != 0

    def weekly_total_cents(self, now_us=None):
        with self._store.lock:
            now_us = self._now_us() if now_us is None else now_us
            return self._store.one("SELECT COALESCE(SUM(amount_cents),0) FROM refunds WHERE status != 'void' AND at_us >= ?",
                                   (now_us - WINDOW_US,))[0]

    # -- decisions -----------------------------------------------------------
    def decide(self, customer_id, transaction_id, amount, *, reason_code=None, description=None,
               scope=None, actor='refunds-agent'):
        decision_id = 'D-' + uuid.uuid4().hex
        raw = {'customer_id': safe_repr(customer_id), 'transaction_id': safe_repr(transaction_id),
               'amount': safe_repr(amount), 'reason_code': safe_repr(reason_code),
               'description_len': len(description) if isinstance(description, str) else None,
               'case_id': getattr(scope, 'case_id', None) if scope is not None else None}
        st = self._store
        actor = clean_text(actor, 40)
        with st.lock:
            try:
                return self._decide_locked(decision_id, raw, customer_id, transaction_id, amount, reason_code, scope, actor)
            except Exception as exc:                       # fail closed, still audited
                st.rollback()
                result = {'decision_id': decision_id, 'outcome': 'denied', 'reason': 'internal error', 'rule': 'R00'}
                body = {**result, 'raw': raw, 'error': type(exc).__name__}
                if not self._audit_or_fallback('refund_decision', decision_id, actor, body):
                    # Not in the audit table (it is in the fallback file). Say so, so callers can return
                    # "try again later" instead of a reference nobody can look up.
                    result['reason'] = 'control store unavailable'
                return result

    def _decide_locked(self, decision_id, raw, customer_id, transaction_id, amount, reason_code, scope, actor):
        st = self._store
        now_us = self._now_us()                            # clock is read exactly once per decision
        st.begin()
        info = {}

        def finish(outcome, reason, rule, **extra):
            result = {'decision_id': decision_id, 'outcome': outcome, 'reason': reason, 'rule': rule, **extra}
            st.append_audit(now_us, 'refund_decision', decision_id, actor,
                            {**result, 'raw': raw, **info,
                             'limits': {'per_txn_cents': PER_TXN_LIMIT_CENTS, 'weekly_cents': WEEKLY_LIMIT_CENTS}})
            st.commit()
            return result

        # R01 authority (read inside the same transaction that commits)
        row = st.one('SELECT revoked FROM authority_state WHERE id = 1')
        if self._stopped or row is None or row[0] != 0:
            return finish('denied', 'authority revoked', 'R01')
        # R02 request shape
        if not (isinstance(customer_id, str) and _ID_RE['customer'].fullmatch(customer_id)
                and isinstance(transaction_id, str) and _ID_RE['txn'].fullmatch(transaction_id)):
            return finish('denied', 'incomplete or malformed request', 'R02')
        if self._require_reason and reason_code not in REASON_CODES:
            return finish('denied', 'incomplete or malformed request', 'R02')
        info.update(customer_id=customer_id, transaction_id=transaction_id)
        # R03 amount
        cents = parse_amount_cents(amount)
        if cents is None:
            return finish('denied', 'invalid amount', 'R03')
        info['amount_cents'] = cents
        # R04 ownership
        txn = st.one('SELECT customer_id, amount_cents FROM transactions WHERE transaction_id = ?', (transaction_id,))
        if txn is None or txn[0] != customer_id:
            return finish('denied', 'transaction not owned by customer', 'R04')
        # R05 case scope (when the caller is scoped, it must match the request)
        if scope is not None:
            case_id = getattr(scope, 'case_id', None)
            ok = st.one("SELECT 1 FROM cases WHERE case_id = ? AND token_sha256 = ? AND status = 'open' "
                        "AND customer_id = ? AND transaction_id = ? AND opened_us >= ?",
                        (case_id if isinstance(case_id, str) else None, token_digest(getattr(scope, '_token', None)),
                         customer_id, transaction_id, now_us - SCOPE_TTL_US))
            if not ok:
                return finish('denied', 'outside case scope', 'R05')
        # R06 not more than the original charge
        if cents > txn[1]:
            return finish('denied', 'exceeds original transaction', 'R06')
        # R07 replay
        if st.one("SELECT 1 FROM refunds WHERE transaction_id = ? AND status != 'void'", (transaction_id,)):
            return finish('denied', 'transaction already refunded', 'R07')
        # R08 existing escalation on this transaction: the admin path is the only path
        esc = st.one('SELECT escalation_id, status FROM escalations WHERE transaction_id = ?', (transaction_id,))
        if esc is not None:
            if esc[1] == 'admin_denied':
                return finish('denied', 'admin decision is final', 'R08', escalation_id=esc[0])
            return finish('escalated', 'escalation already pending', 'R08', escalation_id=esc[0])
        # R09 per-transaction limit
        if cents > PER_TXN_LIMIT_CENTS:
            esc_id = 'E-' + uuid.uuid4().hex
            st.conn.execute("INSERT INTO escalations(escalation_id, transaction_id, customer_id, amount_cents, status, opened_us) "
                            "VALUES (?,?,?,?, 'pending', ?)", (esc_id, transaction_id, customer_id, cents, now_us))
            return finish('escalated', 'over per-transaction limit', 'R09', escalation_id=esc_id)
        # R10 weekly limit, summed from the store inside this transaction
        total = st.one("SELECT COALESCE(SUM(amount_cents),0) FROM refunds WHERE status != 'void' AND at_us >= ?",
                       (now_us - WINDOW_US,))[0]
        info['weekly_total_before_cents'] = total
        if total + cents > WEEKLY_LIMIT_CENTS:
            return finish('denied', 'weekly limit reached', 'R10')
        # R11 reserve + audit in one commit; the bank is only touched afterwards
        status = 'reserved' if self._bank else 'settled'
        st.conn.execute("INSERT INTO refunds(decision_id, transaction_id, customer_id, amount_cents, at_us, status, authority) "
                        "VALUES (?,?,?,?,?,?, 'agent')", (decision_id, transaction_id, customer_id, cents, now_us, status))
        result = finish('approved', 'within limits', 'R11')
        if self._bank:
            return self._settle(result, customer_id, transaction_id, cents, now_us, actor)
        return result

    def _settle(self, result, customer_id, transaction_id, cents, now_us, actor):
        """Still under the store lock. The reservation is already committed, counted and blocking the transaction.

        It is released (void) only when the bank was certainly not called. Once the call has been attempted,
        any error leaves the row reserved, because the money may have moved: it keeps counting toward the week
        and keeps blocking the transaction until someone reconciles it. The idempotency key is per transaction,
        so a retry can never pay the same transaction twice."""
        did = result['decision_id']
        if self.is_revoked():
            self._settlement(did, actor, now_us, 'void', 'authority revoked')
            return {**result, 'outcome': 'denied', 'reason': 'authority revoked', 'rule': 'R12'}
        try:
            self._bank(idempotency_key='refund:' + transaction_id, customer_id=customer_id,
                       transaction_id=transaction_id, amount_cents=cents)
        except Exception as exc:
            self._settlement(did, actor, now_us, 'reserved', 'settlement unknown', error=type(exc).__name__)
            return {**result, 'outcome': 'escalated', 'reason': 'settlement unknown', 'rule': 'R12'}
        self._settlement(did, actor, now_us, 'settled', None)
        return result

    def _settlement(self, did, actor, now_us, status, reason, **extra):
        st = self._store
        body = {'status': status, **({'reason': reason} if reason else {}), **extra}
        try:
            with st.tx():
                st.conn.execute('UPDATE refunds SET status = ? WHERE decision_id = ?', (status, did))
                st.append_audit(now_us, 'settlement', did, actor, body)
        except Exception:                                   # the row stays 'reserved', which is the safe state
            st.fallback_audit('settlement', did, actor, body)

    # -- kill switch -----------------------------------------------------------
    def engage_kill_switch(self, *, actor, reason='', admin=None):
        """Anyone may stop the agent. by_admin in the audit row is True only for a verified admin principal."""
        self._stopped = True                            # this process stops now, whatever happens below
        by_admin = _is_admin(admin)
        return self._set_revoked(1, admin.name if by_admin else clean_text(actor, 40), reason, by_admin)

    def restore_authority(self, admin, reason):
        if not _is_admin(admin):
            did = 'K-' + uuid.uuid4().hex
            body = {'outcome': 'denied', 'reason': 'restore requires admin'}
            with self._store.lock:
                self._audit_or_fallback('kill_switch_denied', did, clean_text(admin, 40), body)
            return {'decision_id': did, **body}
        return self._set_revoked(0, admin.name, reason, True)

    def record_admin_denied(self, purpose, token_presented):
        """Audit a failed attempt to act as admin. The token itself is never recorded."""
        did = 'K-' + uuid.uuid4().hex
        with self._store.lock:
            self._audit_or_fallback('admin_auth_denied', did, 'unauthenticated',
                                    {'outcome': 'denied', 'purpose': clean_text(purpose, 60),
                                     'token_presented': bool(token_presented)})
        return did

    def _set_revoked(self, value, actor, reason, by_admin):
        st = self._store
        did = 'K-' + uuid.uuid4().hex
        reason = clean_text(reason, 200)
        with st.lock:                                   # same lock as decide(): no in-flight decision survives
            body = {'engaged': bool(value), 'reason': reason, 'by_admin': by_admin}
            try:
                now_us = self._stamp() if value else self._now_us()
                with st.tx():
                    prev = st.one('SELECT revoked FROM authority_state WHERE id = 1')
                    st.conn.execute('INSERT OR REPLACE INTO authority_state(id, revoked, changed_us, changed_by, reason) '
                                    'VALUES (1,?,?,?,?)', (value, now_us, actor, reason))
                    st.append_audit(now_us, 'kill_switch', did, actor,
                                    {**body, 'previous': None if prev is None else bool(prev[0])})
            except Exception as exc:
                st.fallback_audit('kill_switch', did, actor, {**body, 'error': type(exc).__name__})
                if value:                               # stopped in this process; the store did not record it
                    return {'decision_id': did, 'outcome': 'ok', 'engaged': True, 'persisted': False}
                return {'decision_id': did, 'outcome': 'denied', 'reason': 'control store unavailable',
                        'engaged': self.is_revoked()}
            if not value:
                self._stopped = False
            return {'decision_id': did, 'outcome': 'ok', 'engaged': bool(value)}

    # -- admin decision on an escalation ---------------------------------------
    def list_escalations(self, admin, status='pending'):
        """Admin only. Returns None for anyone else."""
        if not _is_admin(admin) or status not in ('pending', 'admin_approved', 'admin_denied'):
            return None
        st = self._store
        with st.lock:
            rows = st.all('SELECT escalation_id, transaction_id, customer_id, amount_cents, status, opened_us, decided_by '
                          'FROM escalations WHERE status = ? ORDER BY opened_us', (status,))
        return [{'escalation_id': e, 'transaction_id': t, 'customer_id': c, 'amount': '%d.%02d' % divmod(a, 100),
                 'status': s, 'opened_us': o, 'decided_by': d} for e, t, c, a, s, o, d in rows]

    def decide_escalation(self, admin, escalation_id, approve, reason=''):
        st = self._store
        did = 'A-' + uuid.uuid4().hex
        actor = admin.name if _is_admin(admin) else clean_text(admin, 40)
        shown_id = clean_text(escalation_id, 60)
        note = clean_text(reason, 200)
        with st.lock:
            try:
                now_us = self._now_us()
                with st.tx():
                    return self._decide_escalation_tx(did, actor, shown_id, note, now_us, admin, escalation_id, approve)
            except Exception as exc:                        # fail closed, still audited
                result = {'decision_id': did, 'outcome': 'denied', 'reason': 'internal error', 'escalation_id': shown_id}
                if not self._audit_or_fallback('escalation_decision', did, actor,
                                               {**result, 'admin_reason': note, 'error': type(exc).__name__}):
                    result['reason'] = 'control store unavailable'
                return result

    def _decide_escalation_tx(self, did, actor, shown_id, note, now_us, admin, escalation_id, approve):
        st = self._store

        def finish(outcome, why, **extra):
            result = {'decision_id': did, 'outcome': outcome, 'reason': why, 'escalation_id': shown_id, **extra}
            st.append_audit(now_us, 'escalation_decision', did, actor, {**result, 'admin_reason': note})
            return result

        if not _is_admin(admin) or approve not in (True, False):
            return finish('denied', 'admin decision requires admin')
        esc = st.one('SELECT transaction_id, customer_id, amount_cents, status FROM escalations WHERE escalation_id = ?',
                     (escalation_id,)) if isinstance(escalation_id, str) and escalation_id == shown_id else None
        if esc is None or esc[3] != 'pending':
            return finish('denied', 'no pending escalation')
        txn_id, cust, cents, _ = esc
        if not approve:
            st.conn.execute("UPDATE escalations SET status='admin_denied', decided_us=?, decided_by=? WHERE escalation_id=?",
                            (now_us, admin.name, escalation_id))
            return finish('denied', 'admin denied')
        row = st.one('SELECT revoked FROM authority_state WHERE id = 1')
        if self._stopped or row is None or row[0] != 0:
            return finish('denied', 'authority revoked')
        txn = st.one('SELECT customer_id, amount_cents FROM transactions WHERE transaction_id = ?', (txn_id,))
        if txn is None or txn[0] != cust or cents > txn[1]:
            return finish('denied', 'exceeds original transaction')
        if st.one("SELECT 1 FROM refunds WHERE transaction_id = ? AND status != 'void'", (txn_id,)):
            return finish('denied', 'transaction already refunded')
        total = st.one("SELECT COALESCE(SUM(amount_cents),0) FROM refunds WHERE status != 'void' AND at_us >= ?",
                       (now_us - WINDOW_US,))[0]
        if total + cents > WEEKLY_LIMIT_CENTS:
            return finish('denied', 'weekly limit reached')          # the escalation stays pending
        st.conn.execute("INSERT INTO refunds(decision_id, transaction_id, customer_id, amount_cents, at_us, status, authority) "
                        "VALUES (?,?,?,?,?, 'settled', 'admin')", (did, txn_id, cust, cents, now_us))
        st.conn.execute("UPDATE escalations SET status='admin_approved', decided_us=?, decided_by=? WHERE escalation_id=?",
                        (now_us, admin.name, escalation_id))
        return finish('approved', 'admin approved', amount_cents=cents)
