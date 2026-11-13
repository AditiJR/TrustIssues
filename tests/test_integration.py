"""The merged service: form -> input scan -> orchestrator -> gate (ownership) -> records and refunds agents -> limit control.

Uses a fixed planner, so nothing here calls the Anthropic API.
"""
import pytest
from fastapi.testclient import TestClient

from tests.fakes import FixedPlanner

TOKEN = 'integration-token-0123456789'
ADMIN = {'X-Admin-Token': TOKEN}


def form(customer='C-1', txn='T-1002', amount='80.00', reason='damaged', description=None):
    return {'customer_id': customer, 'transaction_id': txn, 'amount': amount, 'reason': reason,
            'description': description}


@pytest.fixture
def env(isolated_paths, monkeypatch):
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(isolated_paths / 'controls.db'))
    monkeypatch.setenv('TRUSTISSUES_ADMIN_TOKEN', TOKEN)
    monkeypatch.delenv('TRUSTISSUES_RECORDS_SOURCE', raising=False)
    from app.controls import gate
    import app.main as main
    gate._reset_for_tests()
    monkeypatch.setattr(main, 'LOG_DIR', str(isolated_paths))
    planner = FixedPlanner()
    monkeypatch.setattr(main.orchestrator, 'planner', planner)
    with TestClient(main.app) as client:
        yield client, planner, gate, main
    gate._reset_for_tests()


def test_steps_and_the_limit_control_decision_are_returned_together(env):
    client, planner, _, _ = env
    body = client.post('/api/refund-requests', json=form()).json()
    assert body['outcome'] == 'approved' and body['reference'].startswith('D-')
    assert [s['agent'] for s in body['steps']] == ['intake', 'records', 'refunds']
    assert all(s['result']['status'] == 'ok' for s in body['steps'])
    assert len(planner.calls) == 1


def test_amount_over_100_is_escalated_by_the_limit_control_not_the_agent(env):
    client, _, _, _ = env
    body = client.post('/api/refund-requests', json=form(txn='T-1001', amount='250.00')).json()
    assert body['outcome'] == 'escalated'


def test_other_customers_transaction_never_reaches_the_planner_and_is_audited(env):
    client, planner, _, _ = env
    body = client.post('/api/refund-requests', json=form(txn='T-1003', amount='50.00')).json()   # T-1003 is C-2's
    assert body['outcome'] == 'denied' and body['steps'] == []
    assert planner.calls == []
    audit = client.get('/admin/audit', headers=ADMIN).json()['entries']
    denials = [e for e in audit if e['kind'] == 'refund_decision']
    assert [d['reason'] for d in denials] == ['transaction not owned by customer']


def test_kill_switch_before_the_request_stops_the_planner_and_every_step(env):
    client, planner, _, _ = env
    assert client.post('/admin/kill-switch', json={'engaged': True, 'reason': 'test'}, headers=ADMIN).status_code == 200
    body = client.post('/api/refund-requests', json=form()).json()
    assert body['status'] == 'halted' and body['outcome'] == 'denied' and body['steps'] == []
    assert planner.calls == []                      # revoking stops the planner, not just the refund


def test_kill_switch_engaged_mid_case_stops_the_remaining_steps_and_no_refund_is_issued(env, monkeypatch):
    client, _, gate, main = env
    from app import agents

    def intake_then_revoke(case_id, task, case):
        gate.engage_kill_switch(actor='test', reason='revoked mid-case')
        return {'status': 'ok', 'output': 'registered'}

    monkeypatch.setitem(agents.AGENT_REGISTRY, 'intake', intake_then_revoke)
    body = client.post('/api/refund-requests', json=form()).json()
    assert body['status'] == 'halted' and body['outcome'] == 'denied'
    events = [e for e in client.get('/admin/events?case_id=%s' % body['case_id'], headers=ADMIN).json()
              if e['action'] == 'step_start']
    assert [e['agent'] for e in events] == ['intake']            # records and refunds never started
    audit = client.get('/admin/audit', headers=ADMIN).json()['entries']
    assert not [e for e in audit if e['kind'] == 'refund_decision' and e['outcome'] == 'approved']


def test_every_denial_looks_the_same_whether_or_not_the_pair_is_owned(env):
    client, _, _, _ = env
    client.post('/api/refund-requests', json=form())                 # uses T-1002, so a replay is denied
    bodies = [client.post('/api/refund-requests', json=form()).json(),                      # owned, replayed
              client.post('/api/refund-requests', json=form(txn='T-1003')).json(),          # not owned
              client.post('/api/refund-requests', json=form(txn='T-9999')).json()]          # does not exist
    for b in bodies:
        assert b['outcome'] == 'denied' and b['steps'] == []
        b['message'] = b['message'].replace(b['reference'], '<ref>')
    assert len({(b['status'], b['message'], tuple(b['steps'])) for b in bodies}) == 1


def test_plan_that_lists_refunds_twice_requests_one_decision(env):
    client, planner, _, _ = env
    planner.steps = [{'agent': 'refunds', 'task': 'a'}, {'agent': 'refunds', 'task': 'b'}]
    body = client.post('/api/refund-requests', json=form()).json()
    assert body['outcome'] == 'approved'
    audit = client.get('/admin/audit', headers=ADMIN).json()['entries']
    assert len([e for e in audit if e['kind'] == 'refund_decision']) == 1


def test_description_is_scanned_in_the_endpoint_and_an_attack_stops_before_the_planner(env, payloads):
    client, planner, _, _ = env
    attack = payloads['form_free_text']['direct_override']
    body = client.post('/api/refund-requests', json=form(description=attack)).json()
    assert body['status'] == 'quarantined' and body['steps'] == []
    assert planner.calls == []
    audit = client.get('/admin/audit', headers=ADMIN).json()['entries']
    assert not [e for e in audit if e['kind'] == 'refund_decision']          # nothing was decided or paid
    detections = client.get('/admin/detections', headers=ADMIN).json()
    assert any(d.get('source') == 'form' for d in detections)


def test_an_ordinary_description_is_not_quarantined(env):
    client, planner, _, _ = env
    body = client.post('/api/refund-requests', json=form(description='The box arrived crushed.')).json()
    assert body['status'] == 'completed' and len(planner.calls) == 1
