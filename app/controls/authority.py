"""RefundAuthority: the interface redteam/run_refund_chains.py uses, backed by the real limit control.

This is a test facade. Each instance owns a private in-memory store, and kill_switch(False) restores
authority without a credential because the red-team chains call it that way. The service never uses
this class and never hands it to an agent; the service goes through app.controls.gate, where restoring
authority needs the admin token.

    from app.controls.authority import RefundAuthority
"""
from decimal import Decimal

from app.controls.limit_control import AdminPrincipal, LimitControl
from app.controls.limits import PER_TXN_LIMIT_CENTS, WEEKLY_LIMIT_CENTS
from app.controls.store import SEED_TRANSACTIONS, Store

PER_TXN_LIMIT = Decimal(PER_TXN_LIMIT_CENTS) / 100
WEEKLY_LIMIT = Decimal(WEEKLY_LIMIT_CENTS) / 100
TRANSACTIONS = {t: (c, Decimal(a) / 100) for t, c, a in SEED_TRANSACTIONS}   # read-only copy for callers


class RefundAuthority:
    def __init__(self, now=None):
        self._store = Store(':memory:')
        self._lc = LimitControl(self._store, now=now, require_reason=False)
        self._operator = AdminPrincipal('test-operator', AdminPrincipal._MINT)

    def request_refund(self, customer, txn, amount):
        d = self._lc.decide(customer, txn, amount, actor='harness')
        return {'outcome': d['outcome'], 'reason': d['reason'], 'decision_id': d['decision_id']}

    def kill_switch(self, engaged=True):
        if engaged is True:
            self._lc.engage_kill_switch(actor='test-operator', reason='facade')
        elif engaged is False:
            self._lc.restore_authority(self._operator, 'facade')
        else:                                   # anything else fails closed and is logged
            self._lc.engage_kill_switch(actor='test-operator', reason='non-boolean kill_switch argument')

    def weekly_total(self):
        return Decimal(self._lc.weekly_total_cents()) / 100

    @property
    def revoked(self):
        return self._lc.is_revoked()

    @property
    def audit(self):
        return tuple(self._store.read_audit(kinds=('refund_decision', 'kill_switch')))

    @property
    def issued(self):
        with self._store.lock:
            rows = self._store.all("SELECT transaction_id, customer_id, amount_cents, at_us FROM refunds WHERE status != 'void'")
        return tuple({'txn': t, 'customer': c, 'amount': Decimal(a) / 100, 'at_us': at} for t, c, a, at in rows)
