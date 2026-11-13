"""The only surface the service and the agents import.

It offers no restore, no limit setter and no function that takes a case id. Admin actions are
reachable only through admin(token), which needs the admin credential.
"""
import os
import threading

from app.controls.access_control import AccessControl, CaseScope, authenticate_admin
from app.controls.limit_control import LimitControl
from app.controls.store import Store

_state = {}
_init_lock = threading.Lock()
_NO_SCOPE = CaseScope('none', 'none', 'none', 'none')

MESSAGES = {
    'approved': 'Your refund was approved and will be returned to your original payment method. Reference: %s',
    'escalated': 'Your request needs review by an administrator. You will hear back by email. Reference: %s',
    'denied': 'We could not approve this request. Reference: %s',
}


def db_path():
    """TRUSTISSUES_CONTROL_DB, or logs/controls.db next to the app's other runtime output."""
    return os.environ.get('TRUSTISSUES_CONTROL_DB') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', 'logs', 'controls.db')


def _controls():
    """Process-wide controls, opened on first use. The store path is read once; changing the environment
    variable afterwards has no effect until the process restarts."""
    if not _state:
        with _init_lock:
            if not _state:
                path = db_path()
                if path != ':memory:':
                    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                store = Store(path)
                lc = LimitControl(store)
                _state.update(store=store, lc=lc, ac=AccessControl(store, lc))
    return _state


def _reset_for_tests():
    """Drop the process-wide controls so the next call reopens the store named by the environment."""
    with _init_lock:
        store = _state.get('store')
        if store is not None:
            store.conn.close()
        _state.clear()


def _with_message(decision):
    return {**decision, 'message': MESSAGES[decision['outcome']] % decision['decision_id']}


UNAVAILABLE = 'control store unavailable'


def public_view(decision):
    """What a customer may see. The reason and rule stay in the audit log: returning them would tell a
    caller whether a customer/transaction pair exists. A decision whose reason is UNAVAILABLE was not
    written to the audit table; answer "try again later" for it instead of sending this view."""
    return {'outcome': decision['outcome'], 'message': decision['message'], 'reference': decision['decision_id']}


def open_case(customer_id, transaction_id, *, actor='intake'):
    return _controls()['ac'].open_case(customer_id, transaction_id, actor=actor)


def records_for(scope, *, actor='records-agent'):
    return _controls()['ac'].records_for(scope, actor=actor)


def close_case(scope):
    return _controls()['ac'].close_case(scope)


def request_refund(scope, amount, reason_code, description=None, *, actor='refunds-agent'):
    """Customer and transaction come from the scope, never from the caller."""
    d = _controls()['lc'].decide(getattr(scope, 'customer_id', None), getattr(scope, 'transaction_id', None), amount,
                                 reason_code=reason_code, description=description, scope=scope, actor=actor)
    return _with_message(d)


def handle_refund_form(customer_id, transaction_id, amount, reason_code, description=None):
    """Deterministic path for POST /api/refund-requests: ownership check, then limit control.
    Returns the full decision; pass it through public_view() before sending it to a customer."""
    scope, denial = open_case(customer_id, transaction_id)
    if scope is None:
        # No case exists. Run the request through limit control with a scope that matches nothing, so the
        # refusal still gets a decision id and an audit row and can never turn into an approval.
        d = _controls()['lc'].decide(customer_id, transaction_id, amount, reason_code=reason_code,
                                     description=description, scope=_NO_SCOPE, actor='intake')
        return _with_message(d)
    try:
        return request_refund(scope, amount, reason_code, description)
    finally:
        close_case(scope)


def engage_kill_switch(*, actor, reason=''):
    """Anyone may stop the agent. Only an admin may start it again (see admin()). The actor name given here
    is a label, not an identity: the audit row is marked by_admin only when the admin console is used."""
    return _controls()['lc'].engage_kill_switch(actor=actor, reason=reason)


def is_revoked():
    return _controls()['lc'].is_revoked()


class AdminConsole:
    """Admin-only actions. Obtained from admin(token); there is no other way to build a working one."""

    def __init__(self, principal, controls):
        self._p, self._c = principal, controls

    def list_escalations(self, status='pending'):
        return self._c['lc'].list_escalations(self._p, status)

    def decide_escalation(self, escalation_id, approve, reason=''):
        return self._c['lc'].decide_escalation(self._p, escalation_id, approve, reason)

    def engage_kill_switch(self, reason=''):
        return self._c['lc'].engage_kill_switch(actor='admin', reason=reason, admin=self._p)

    def restore_authority(self, reason):
        return self._c['lc'].restore_authority(self._p, reason)

    def read_audit(self, kinds=None):
        return self._c['store'].read_audit(kinds)

    def verify_audit_chain(self):
        return self._c['store'].verify_audit_chain()

    def audit_head(self):
        return self._c['store'].audit_head()


def admin(token, purpose=''):
    """Admin console, or None unless token matches TRUSTISSUES_ADMIN_TOKEN. A refused attempt is audited
    with its purpose; the token is never recorded."""
    principal = authenticate_admin(token)
    if principal is None:
        _controls()['lc'].record_admin_denied(purpose, token is not None)
        return None
    return AdminConsole(principal, _controls())
