"""mock bank, run through Blake's real LimitControl (bank= hook) and on its own."""
import ast
import os
import random
import sqlite3

import pytest

from app.bank import OPENING_BALANCE_CENTS, BankRefused, BankRejected, MockBank
from app.controls.limit_control import LimitControl
from app.controls.store import Store

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PG_URL = os.environ.get('TRUSTISSUES_TEST_PG_URL')


class Spy:
    """counts bank calls and passes them on."""

    def __init__(self, bank):
        self.bank, self.calls = bank, []

    def __call__(self, **kw):
        self.calls.append(kw)
        return self.bank(**kw)


@pytest.fixture
def bank(tmp_path):
    b = MockBank(str(tmp_path / 'bank.db'))
    yield b
    b.close()


@pytest.fixture
def setup(bank):
    """limit control on its own in-memory store, with the bank plugged in the way gate.py would do it."""
    spy = Spy(bank)
    lc = LimitControl(Store(':memory:'), bank=spy)
    bank._is_revoked = lambda: lc.is_revoked()
    return lc, bank, spy


def refund_row(lc, txn):
    return lc._store.one('SELECT status FROM refunds WHERE transaction_id = ?', (txn,))


def events(action):
    from app.monitoring.audit import get_audit_log
    return get_audit_log().read(action=action)


# ---------------------------------------------------------------- through limit control
def test_approved_refund_credits_the_balance(setup):
    lc, bank, spy = setup
    d = lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    assert (d['outcome'], d['rule']) == ('approved', 'R11')
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS + 2000
    assert refund_row(lc, 'T-1002') == ('settled',)
    [credit] = [e for e in bank.ledger('C-1') if e['kind'] == 'refund_credit']
    assert (credit['idempotency_key'], credit['amount_cents'], credit['balance_after_cents']) == (
        'refund:T-1002', 2000, OPENING_BALANCE_CENTS + 2000)
    assert spy.calls == [{'idempotency_key': 'refund:T-1002', 'customer_id': 'C-1', 'transaction_id': 'T-1002',
                          'amount_cents': 2000}]
    [e] = events('bank_credit')
    assert e['transaction_id'] == 'T-1002' and e['amount_cents'] == 2000


def test_retry_never_pays_twice(setup):
    lc, bank, spy = setup
    lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    # limit control itself refuses a second refund on the same transaction, so the bank never hears about it
    d = lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    assert d['outcome'] == 'denied' and len(spy.calls) == 1
    # and if the same call does reach the bank again (a retry after a timeout), it's a replay, not a second credit
    again = bank(**spy.calls[0])
    assert again['replayed'] is True
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS + 2000
    assert len(events('bank_credit_replayed')) == 1


def test_bank_error_means_settlement_unknown(bank):
    def broken(**kw):
        raise ConnectionError('bank timed out')

    lc = LimitControl(Store(':memory:'), bank=broken)
    d = lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    assert (d['outcome'], d['reason'], d['rule']) == ('escalated', 'settlement unknown', 'R12')
    assert refund_row(lc, 'T-1002') == ('reserved',)             # money might have moved, so it stays counted
    assert lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')['outcome'] == 'denied'   # still blocked
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS


@pytest.mark.parametrize('customer,txn,amount,outcome', [
    ('C-1', 'T-1001', '150.00', 'escalated'),                    # over $100
    ('C-2', 'T-1001', '20.00', 'denied'),                        # not C-2's transaction
    ('C-1', 'T-1002', '90.00', 'denied'),                        # more than the $80 charge
])
def test_denied_or_escalated_never_touches_the_bank(setup, customer, txn, amount, outcome):
    lc, bank, spy = setup
    assert lc.decide(customer, txn, amount, reason_code='damaged')['outcome'] == outcome
    assert spy.calls == []
    assert {e['kind'] for e in bank.ledger()} == {'opening'}


def test_weekly_limit_stops_the_bank_too(setup):
    lc, bank, spy = setup
    for txn in ('T-1004', 'T-1005', 'T-1006', 'T-1007', 'T-1008'):
        assert lc.decide('C-1', txn, '100.00', reason_code='damaged')['outcome'] == 'approved'
    d = lc.decide('C-1', 'T-1009', '100.00', reason_code='damaged')
    assert (d['outcome'], d['reason']) == ('denied', 'weekly limit reached')
    assert len(spy.calls) == 5
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS + 50000


def test_kill_switch_before_the_decision(setup):
    lc, bank, spy = setup
    lc.engage_kill_switch(actor='test', reason='test')
    d = lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    assert (d['outcome'], d['rule']) == ('denied', 'R01')
    assert spy.calls == [] and bank.balance_cents('C-1') == OPENING_BALANCE_CENTS


def test_kill_switch_after_limit_controls_check_is_caught_by_the_bank(setup):
    lc, bank, spy = setup

    def revoke_mid_credit():
        # stands in for an admin hitting the switch after limit control's R12 check, while the bank is crediting
        lc.engage_kill_switch(actor='test', reason='mid-credit')
        return lc.is_revoked()

    bank._is_revoked = revoke_mid_credit
    d = lc.decide('C-1', 'T-1002', '20.00', reason_code='damaged')
    assert (d['outcome'], d['reason']) == ('escalated', 'settlement unknown')
    assert len(spy.calls) == 1
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS
    assert {e['kind'] for e in bank.ledger()} == {'opening'}
    assert events('bank_credit_refused')


# ---------------------------------------------------------------- the bank on its own (sqlite, and postgres if set)
@pytest.fixture(params=['sqlite'] + (['postgres'] if PG_URL else []))
def any_bank(request, tmp_path):
    b = MockBank(str(tmp_path / 'bank.db') if request.param == 'sqlite' else PG_URL)
    yield b
    b.close()


def _txn():
    # postgres keeps rows between runs and the ledger is append-only, so use fresh ids
    return 'T-%d' % random.randint(10 ** 8, 10 ** 9 - 1)


def credit(bank, txn, amount=500, customer='C-1', key=None):
    return bank(idempotency_key=key or 'refund:' + txn, customer_id=customer, transaction_id=txn, amount_cents=amount)


def test_seeded_accounts_and_ledger_add_up(any_bank):
    credit(any_bank, _txn())
    for customer in ('C-1', 'C-2'):
        rows = any_bank.ledger(customer)
        assert rows[0]['kind'] == 'opening' and rows[0]['amount_cents'] == OPENING_BALANCE_CENTS
        assert sum(r['amount_cents'] for r in rows) == any_bank.balance_cents(customer)


def test_same_key_twice_credits_once(any_bank):
    txn, before = _txn(), any_bank.balance_cents('C-1')
    first, second = credit(any_bank, txn), credit(any_bank, txn)
    assert second == {**first, 'replayed': True}
    assert any_bank.balance_cents('C-1') == before + 500


def test_reused_key_with_different_details_is_rejected(any_bank):
    txn, before = _txn(), any_bank.balance_cents('C-1')
    credit(any_bank, txn)
    with pytest.raises(BankRejected):
        credit(any_bank, txn, amount=9999)
    with pytest.raises(BankRejected):
        credit(any_bank, txn, customer='C-2')
    assert any_bank.balance_cents('C-1') == before + 500


@pytest.mark.parametrize('kw', [
    {'customer_id': 'C-999'},                  # no account
    {'amount_cents': 0}, {'amount_cents': -500},
    {'amount_cents': True}, {'amount_cents': 5.0}, {'amount_cents': '500'}, {'amount_cents': 10 ** 12},
    {'customer_id': 'C-1; DROP TABLE bank_accounts'}, {'customer_id': None},
    {'transaction_id': 'T-abc'}, {'transaction_id': 1002},
    {'idempotency_key': ''}, {'idempotency_key': 'x' * 101}, {'idempotency_key': None},
])
def test_bad_input_is_rejected_and_credits_nothing(any_bank, kw):
    txn = _txn()
    args = {'idempotency_key': 'refund:' + txn, 'customer_id': 'C-1', 'transaction_id': txn, 'amount_cents': 500, **kw}
    before = {c: any_bank.balance_cents(c) for c in ('C-1', 'C-2')}
    with pytest.raises(BankRejected):
        any_bank(**args)
    assert {c: any_bank.balance_cents(c) for c in ('C-1', 'C-2')} == before


def test_refuses_when_the_kill_switch_cant_be_read(bank):
    def unreadable():
        raise sqlite3.OperationalError('control store down')

    bank._is_revoked = unreadable
    with pytest.raises(BankRefused):
        credit(bank, _txn())
    assert bank.balance_cents('C-1') == OPENING_BALANCE_CENTS


@pytest.mark.parametrize('sql', ["UPDATE bank_ledger SET amount_cents = 1", 'DELETE FROM bank_ledger'])
def test_ledger_is_append_only(any_bank, sql):
    with pytest.raises(Exception, match='append-only'):
        any_bank.conn.execute(sql)
    any_bank._rollback()


# ---------------------------------------------------------------- only limit control can reach it
def test_nothing_in_app_imports_the_bank_except_the_gate():
    allowed = {os.path.join('app', 'bank.py'), os.path.join('app', 'controls', 'gate.py')}
    offenders = []
    for folder, _, files in os.walk(os.path.join(ROOT, 'app')):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, ROOT)
            with open(path, encoding='utf-8') as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ''] + ['%s.%s' % (node.module, a.name) for a in node.names]
                if any(n == 'app.bank' or n.startswith('app.bank.') for n in names) and rel not in allowed:
                    offenders.append(rel)
    assert offenders == []


def test_no_agent_or_route_leads_to_the_bank():
    from app.agents import AGENT_REGISTRY
    import app.main as main
    assert not any('bank' in name for name in AGENT_REGISTRY)
    assert not any('bank' in getattr(r, 'path', '') for r in main.app.routes)
