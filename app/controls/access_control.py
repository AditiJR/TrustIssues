"""Access control on customer and financial records, scoped to the case at hand.

Deny by default. A record is released only to a holder of a live CaseScope, and only the
record that scope is bound to. Scopes are issued in code by open_case() after the ownership
check; nothing a model writes can create or widen one. Every allow and every deny is audited;
an allow that cannot be audited is not allowed.
"""
import hmac
import json
import os
import secrets
import uuid

from app.controls.limit_control import AdminPrincipal
from app.controls.limits import SCOPE_TTL_US
from app.controls.store import clean_text, safe_repr, storable, token_digest

AGENT_FIELDS = ('customer_id', 'email', 'account_last4')        # account_no is never released to agents
MIN_ADMIN_TOKEN_LEN = 16
_DENIED = {'allowed': False, 'reason': 'access denied'}
_AT = object()                                                  # placeholder for the audit timestamp in _record()
_ABSENT = object()


def authenticate_admin(token):
    """Return an AdminPrincipal if token equals TRUSTISSUES_ADMIN_TOKEN, else None.

    There is no admin unless the configured token is printable ASCII and at least 16 characters long."""
    expected = os.environ.get('TRUSTISSUES_ADMIN_TOKEN', '')
    if len(expected) < MIN_ADMIN_TOKEN_LEN or not expected.isascii() or not expected.isprintable():
        return None
    if not isinstance(token, str) or not token.isascii():
        return None
    if not hmac.compare_digest(token.encode('ascii'), expected.encode('ascii')):
        return None
    return AdminPrincipal('admin', AdminPrincipal._MINT)


class CaseScope:
    """Capability for one case. Issued only by AccessControl.open_case. The fields are informational:
    every check re-reads the binding from the store by case_id + token."""
    __slots__ = ('case_id', 'customer_id', 'transaction_id', '_token')

    def __init__(self, case_id, customer_id, transaction_id, token):
        object.__setattr__(self, 'case_id', case_id)
        object.__setattr__(self, 'customer_id', customer_id)
        object.__setattr__(self, 'transaction_id', transaction_id)
        object.__setattr__(self, '_token', token)

    def __setattr__(self, *a):
        raise AttributeError('CaseScope is read-only')

    def __repr__(self):
        return 'CaseScope(%r)' % (self.case_id,)                # never prints the token


class AccessControl:
    def __init__(self, store, limit_control):
        self._store, self._lc = store, limit_control

    def _record(self, kind, actor, body, statements=(), must=False):
        """One transaction: optional writes plus the audit row, stamped with one clock reading.
        Caller holds the store lock. If the store refuses, the row goes to the fallback sink; with
        must=True the failure is also raised, so the caller can refuse what it was about to allow."""
        st = self._store
        actor = clean_text(actor, 40)
        try:
            at = self._lc._stamp()
            with st.tx():
                for sql, args in statements:
                    st.conn.execute(sql, tuple(at if a is _AT else a for a in args))
                st.append_audit(at, kind, 'R-' + uuid.uuid4().hex, actor, body)
        except Exception:
            st.fallback_audit(kind, 'R-' + uuid.uuid4().hex, actor, body)
            if must:
                raise

    def open_case(self, customer_id, transaction_id, *, actor='intake'):
        """Return (CaseScope, None) or (None, denial dict). Ownership is checked here, before any policy step."""
        st = self._store
        raw = {'customer_id': safe_repr(customer_id), 'transaction_id': safe_repr(transaction_id)}
        with st.lock:
            try:
                if self._lc.is_revoked():
                    reason = 'authority revoked'
                elif not (storable(customer_id) and storable(transaction_id)):
                    reason = 'incomplete or malformed request'
                else:
                    row = st.one('SELECT customer_id FROM transactions WHERE transaction_id = ?', (transaction_id,))
                    reason = None if row and row[0] == customer_id else 'transaction not owned by customer'
                if reason is None:
                    case_id, token = 'CASE-' + uuid.uuid4().hex[:12], secrets.token_hex(16)
                    self._record('case_open', actor,
                                 {'outcome': 'allowed', 'case_id': case_id, 'customer_id': customer_id,
                                  'transaction_id': transaction_id},
                                 [("INSERT INTO cases VALUES (?,?,?,?, 'open', ?)",
                                   (case_id, token_digest(token), customer_id, transaction_id, _AT))], must=True)
                    return CaseScope(case_id, customer_id, transaction_id, token), None
            except Exception:
                st.rollback()
                reason = 'internal error'
            self._record('case_open', actor, {'outcome': 'denied', 'reason': reason, 'raw': raw})
            return None, {'outcome': 'denied', 'reason': reason}

    def close_case(self, scope, *, actor='orchestrator'):
        """Close the case this scope is bound to. Returns True only if a live case was closed."""
        st = self._store
        case_id = getattr(scope, 'case_id', None)
        shown = clean_text(case_id, 60)
        with st.lock:
            closed = False
            try:
                with st.tx():
                    cur = st.conn.execute("UPDATE cases SET status = 'closed' WHERE case_id = ? AND token_sha256 = ? "
                                          "AND status = 'open'",
                                          (case_id if storable(case_id) else None, token_digest(getattr(scope, '_token', None))))
                    closed = cur.rowcount == 1
                    st.append_audit(self._lc._stamp(), 'case_close', 'R-' + uuid.uuid4().hex, clean_text(actor, 40),
                                    {'case_id': shown, 'outcome': 'closed' if closed else 'denied',
                                     **({} if closed else {'reason': 'no live case for this scope'})})
            except Exception:
                closed = False
                st.fallback_audit('case_close', 'R-' + uuid.uuid4().hex, clean_text(actor, 40),
                                  {'case_id': shown, 'outcome': 'denied', 'reason': 'internal error'})
            return closed

    def records_for(self, scope, *, actor='records-agent'):
        return RecordsGateway(self, scope, actor)

    def _check(self, scope, actor, action, want_customer=None, want_txn=None):
        """Return the stored (customer_id, transaction_id) for a live scope, or None after logging a denial.
        Caller holds the store lock."""
        st = self._store
        case_id = getattr(scope, 'case_id', None)
        try:
            if self._lc.is_revoked():
                reason = 'authority revoked'
            else:
                row = st.one('SELECT customer_id, transaction_id, status, opened_us FROM cases '
                             'WHERE case_id = ? AND token_sha256 = ?',
                             (case_id if storable(case_id) else None, token_digest(getattr(scope, '_token', None))))
                if row is None:
                    reason = 'invalid case scope'
                elif row[2] != 'open':
                    reason = 'case closed'
                elif row[3] < self._lc._now_us() - SCOPE_TTL_US:
                    reason = 'case scope expired'
                elif (want_customer is not None and want_customer != row[0]) or (want_txn is not None and want_txn != row[1]):
                    reason = 'outside case scope'
                else:
                    self._record('records_access', actor, {'outcome': 'allowed', 'action': action, 'case_id': case_id},
                                 must=True)
                    return row[0], row[1]
        except Exception:
            st.rollback()
            reason = 'internal error'
        self._record('records_access', actor,
                     {'outcome': 'denied', 'reason': reason, 'action': action, 'case_id': clean_text(case_id, 60),
                      'requested': {'customer_id': safe_repr(want_customer, 80), 'transaction_id': safe_repr(want_txn, 80)}})
        return None


class RecordsGateway:
    """What the Records agent holds. No method takes a case id, so the model cannot pick a case.
    Callers learn only 'access denied'; the specific reason goes to the audit log."""

    def __init__(self, ac, scope, actor):
        self._ac, self._scope, self._actor = ac, scope, actor

    def get_customer(self, customer_id=None, *, email=None):
        """The case's own customer record (customer_id, email, account_last4). Asking for anyone else is denied."""
        st = self._ac._store
        with st.lock:
            try:
                if email is not None:
                    row = st.one('SELECT customer_id FROM customers WHERE email = ?', (email,)) if storable(email) else None
                    by_email = row[0] if row else '<unknown email>'
                    if customer_id is not None and customer_id != by_email:
                        by_email = '<mismatched id and email>'
                    customer_id = by_email
                bound = self._ac._check(self._scope, self._actor, 'get_customer', want_customer=customer_id)
                if bound is None:
                    return dict(_DENIED)
                row = st.one('SELECT customer_id, email, account_last4 FROM customers WHERE customer_id = ?', (bound[0],))
                if row is None:
                    return dict(_DENIED)
                return {'allowed': True, 'record': dict(zip(AGENT_FIELDS, row))}
            except Exception:
                st.rollback()
                return dict(_DENIED)

    def get_transaction(self, transaction_id=None):
        """The case's own transaction. Asking for any other transaction is denied."""
        st = self._ac._store
        with st.lock:
            try:
                bound = self._ac._check(self._scope, self._actor, 'get_transaction', want_txn=transaction_id)
                if bound is None:
                    return dict(_DENIED)
                row = st.one('SELECT transaction_id, customer_id, amount_cents FROM transactions WHERE transaction_id = ?', (bound[1],))
                if row is None:
                    return dict(_DENIED)
                return {'allowed': True, 'record': {'transaction_id': row[0], 'customer_id': row[1], 'amount_cents': row[2]}}
            except Exception:
                st.rollback()
                return dict(_DENIED)

    def recipient(self):
        """The only address outbound mail for this case may go to: the one on file. None if the scope is not live."""
        rec = self.get_customer()
        return rec['record']['email'] if rec['allowed'] else None

    def retrieval_filter(self):
        """Metadata filter the vector-DB query must apply. Policy chunks are the ones tagged customer_id None."""
        with self._ac._store.lock:
            bound = self._ac._check(self._scope, self._actor, 'retrieval_filter')
        if bound is None:
            return None
        return {'customer_id': bound[0], 'transaction_id': bound[1], 'case_id': self._scope.case_id}

    def filter_chunks(self, chunks):
        """Post-filter for retrieved chunks. A chunk is kept only if all of these hold:
          - it is a dict tagged customer_id, at the top level or under 'metadata', as None (policy text)
            or as this case's customer; if both levels carry the tag they must agree;
          - any transaction_id tag is None or this case's transaction;
          - it has no account_no field and no customer's full account number appears anywhere in it.
        Everything else is dropped, and the drop is logged. Untagged chunks are dropped."""
        try:
            items = list(chunks)                                # read the caller's iterable before taking the lock
        except Exception:
            items = None
        st = self._ac._store
        with st.lock:
            bound = self._ac._check(self._scope, self._actor, 'filter_chunks')
            if bound is None:
                return []
            try:
                if items is None:
                    self._ac._record('records_access', self._actor,
                                     {'outcome': 'denied', 'reason': 'unreadable chunk list', 'action': 'filter_chunks',
                                      'case_id': self._scope.case_id})
                    return []
                account_numbers = [r[0] for r in st.all('SELECT account_no FROM customers')]
                keep = [c for c in items if _chunk_allowed(c, bound, account_numbers)]
                if len(keep) != len(items):
                    self._ac._record('records_access', self._actor,
                                     {'outcome': 'denied', 'reason': 'outside case scope', 'action': 'filter_chunks',
                                      'dropped': len(items) - len(keep), 'case_id': self._scope.case_id}, must=True)
                return keep
            except Exception:
                st.rollback()
                return []


def _tags(chunk, key):
    """Every value the chunk carries for key: top level and under 'metadata'."""
    meta = chunk.get('metadata')
    sources = (chunk, meta if isinstance(meta, dict) else {})
    return [src[key] for src in sources if key in src]


def _chunk_allowed(chunk, bound, account_numbers):
    if not isinstance(chunk, dict):
        return False
    owners = _tags(chunk, 'customer_id')
    if not owners or any(o != owners[0] for o in owners):       # untagged, or the two levels disagree
        return False
    owner = owners[0]
    if not (owner is None or (isinstance(owner, str) and owner == bound[0])):
        return False
    for txn in _tags(chunk, 'transaction_id'):
        if not (txn is None or (isinstance(txn, str) and txn == bound[1])):
            return False
    if _tags(chunk, 'account_no'):
        return False
    try:
        text = json.dumps(chunk, default=str, ensure_ascii=False)
    except Exception:
        return False
    return not any(number and number in text for number in account_numbers)
