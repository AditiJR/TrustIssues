"""HTTP: admin routes for policies, detection and audit, and the starter endpoints still working."""
import json

import pytest
from fastapi.testclient import TestClient

TOKEN = 'test-admin-token-0123456789'


@pytest.fixture
def client(isolated_paths, monkeypatch):
    monkeypatch.setenv('TRUSTISSUES_ADMIN_TOKEN', TOKEN)
    import app.main as main
    monkeypatch.setattr(main, 'LOG_DIR', str(isolated_paths))
    with TestClient(main.app) as c:
        yield c


ADMIN = {'X-Admin-Token': TOKEN}


@pytest.mark.parametrize('method,path', [('get', '/admin/policies'), ('post', '/admin/policies/search'),
                                         ('get', '/admin/detections'), ('get', '/admin/events/verify'),
                                         ('post', '/admin/detect')])
def test_admin_routes_need_token(client, method, path):
    r = client.request(method.upper(), path, headers={'X-Admin-Token': 'wrong-token-wrong-token'}, json={})
    assert r.status_code == 403
    assert client.request(method.upper(), path, json={}).status_code == 403


def test_refused_admin_attempt_is_logged(client):
    client.get('/admin/policies', headers={'X-Admin-Token': 'nope'})
    d = client.get('/admin/detections', headers=ADMIN).json()
    assert any(e['action'] == 'admin_auth_refused' for e in d)


def test_no_admin_without_configured_token(client, monkeypatch):
    monkeypatch.setenv('TRUSTISSUES_ADMIN_TOKEN', 'short')
    assert client.get('/admin/policies', headers={'X-Admin-Token': 'short'}).status_code == 403


def test_policy_upload_search_download(client, payloads):
    assert client.get('/admin/policies', headers=ADMIN).json()[0]['status'] == 'approved'
    up = client.post('/admin/policies', headers=ADMIN, json={
        'doc_name': 'email-policy', 'title': 'Email policy',
        'text': '# Replies\n\nReplies go only to the address on file.\n\n# Bad\n\n'
                + payloads['retrieved_content']['poisoned_policy_chunk']}).json()
    assert up['version'] == 1 and len(up['quarantined']) == 1
    assert client.get('/admin/policies/quarantine', headers=ADMIN).json()[0]['doc_name'] == 'email-policy'
    hits = client.post('/admin/policies/search', headers=ADMIN, json={'query': 'damaged item refund'}).json()
    assert hits and 'provenance' in hits[0]
    doc = client.get('/admin/policies/refund-policy/1', headers=ADMIN).json()
    assert doc['version'] == 1 and '$100' in doc['text']
    assert client.get('/admin/policies/refund-policy/9', headers=ADMIN).status_code == 404


def test_pending_then_approve_over_http(client):
    up = client.post('/admin/policies', headers=ADMIN, json={'text': '# A\n\nnew rule', 'approve': False}).json()
    assert up['status'] == 'pending'
    r = client.post('/admin/policies/refund-policy/%d/approve' % up['version'], headers=ADMIN)
    assert r.json()['status'] == 'approved'
    assert client.post('/admin/policies/refund-policy/%d/approve' % up['version'], headers=ADMIN).status_code == 409


def test_detect_endpoint_and_detections_feed(client, payloads):
    r = client.post('/admin/detect', headers=ADMIN, json={'text': payloads['form_free_text']['direct_override'],
                                                          'customer_id': 'C-1'}).json()
    assert r['verdict'] == 'malicious' and 'INJ-OVERRIDE' in r['rule_ids'] and 'normalized_text' not in r
    feed = client.get('/admin/detections?min_severity=high', headers=ADMIN).json()
    assert any(e['action'] == 'attack_detected' for e in feed)


def test_tasks_still_work_one_entry_with_detection(client, payloads):
    """Starter /tasks: one log entry per call (RT-18), detection folded in, verdict not returned."""
    r = client.post('/tasks', json={'task': payloads['form_free_text']['direct_override'], 'data': {}})
    assert r.status_code == 200 and 'detection' not in json.dumps(r.json())
    plan = [e for e in client.get('/logs', headers=ADMIN).json() if e['action'] == 'plan_and_simulate']
    assert len(plan) == 1 and plan[0]['detection']['verdict'] == 'malicious' and plan[0]['severity'] == 'high'
    assert client.get('/admin/detections', headers=ADMIN).json()


def test_logs_do_not_leak_customer_data(client, payloads):
    """RT-19: customer data is masked when written, so even an admin reading /logs does not see it."""
    c1 = payloads['customers']['C-1']
    client.post('/tasks', json={'task': 'refund to %s acct %s' % (c1['email'], c1['account_no']), 'data': {}})
    resp = client.get('/logs', headers=ADMIN)
    body = resp.text
    assert resp.status_code == 200
    assert c1['email'] not in body and c1['account_no'] not in body


def test_rt01_and_audit_verify_and_monitor(client):
    assert client.post('/tests/rt-01').json()['summary']['flagged_count'] == 2
    v = client.get('/admin/events/verify', headers=ADMIN).json()
    assert v['ok'] and v['chained'] >= 2
    assert isinstance(client.post('/admin/monitor/run', headers=ADMIN).json(), list)
    case = client.get('/admin/events?action=service_started', headers=ADMIN).json()
    assert case and case[0]['actor'] == 'service'


def test_records_lookup_demo(client, payloads):
    ok = client.post('/admin/records/lookup', headers=ADMIN, json={'customer_id': 'C-1', 'transaction_id': 'T-1002'})
    assert ok.json()['status'] == 'ok' and ok.json()['record']['customer']['account_last4'] == '2333'
    inj = client.post('/admin/records/lookup', headers=ADMIN, json={
        'customer_id': 'C-1', 'transaction_id': 'T-1002', 'task': payloads['records_probes']['direct_other_customer']})
    assert inj.json()['record']['task_flagged'] and 'C-2' not in inj.text and '000111222333' not in inj.text
    other = client.post('/admin/records/lookup', headers=ADMIN, json={'customer_id': 'C-1', 'transaction_id': 'T-1003'})
    assert other.json()['status'] == 'denied'
    assert client.post('/admin/records/lookup', json={'customer_id': 'C-1', 'transaction_id': 'T-1002'}).status_code == 403
