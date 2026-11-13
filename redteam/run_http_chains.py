#!/usr/bin/env python3
"""Red-team chains against the running service over HTTP (in-process TestClient, no network).

Unlike run_refund_chains.py, which calls the limit control through a test facade, these go through
app.main: the real routes, admin-token check, orchestrator and audit trail.

  RT-34  Unauthorized kill-switch restore

Each chain records control_held=True when the control held. False is a finding.
Everything runs against a private temp database and event log with a made-up admin token and synthetic data.
The planner is replaced by a fixed one so nothing calls the Anthropic API.

Usage (from repo root): .venv/bin/python redteam/run_http_chains.py
Evidence: redteam/evidence/http_chains_<ts>.json
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

ADMIN_TOKEN = 'redteam-http-token-0123456789'


class FixedPlanner:
    """intake, records, refunds. A stand-in for the LLM planner."""
    def plan(self, case_id, request):
        return [{'agent': 'intake', 'task': 'Register the case.'},
                {'agent': 'records', 'task': "Look up this customer's own record."},
                {'agent': 'refunds', 'task': 'Request the refund decision.'}]


def setup():
    """Private control DB, event log and RAG DB, then the app. Env is set before app.main is imported."""
    tmp = tempfile.mkdtemp(prefix='rt_http_')
    os.environ['TRUSTISSUES_CONTROL_DB'] = os.path.join(tmp, 'controls.db')
    os.environ['TRUSTISSUES_ADMIN_TOKEN'] = ADMIN_TOKEN
    os.environ['TRUSTISSUES_EVENT_LOG'] = os.path.join(tmp, 'events.jsonl')
    os.environ['TRUSTISSUES_RAG_DB'] = os.path.join(tmp, 'rag.db')
    os.environ.pop('TRUSTISSUES_RECORDS_SOURCE', None)
    from fastapi.testclient import TestClient
    from app.controls import gate
    import app.main as main
    gate._reset_for_tests()
    main.LOG_DIR = tmp
    main.orchestrator.planner = FixedPlanner()
    return TestClient(main.app, raise_server_exceptions=False), gate, main


def form(txn='T-1004', amount='10.00'):
    return {'customer_id': 'C-1', 'transaction_id': txn, 'amount': amount, 'reason': 'damaged'}


def chain_rt34_unauthorized_restore():
    client, gate, main = setup()
    admin = {'X-Admin-Token': ADMIN_TOKEN}
    body = {'engaged': False, 'reason': 'attacker restore'}
    problems, attempts = [], []

    # 1. an admin stops the agent
    r = client.post('/admin/kill-switch', json={'engaged': True, 'reason': 'incident'}, headers=admin)
    if r.status_code != 200 or not gate.is_revoked():
        return False, {'setup_failed': {'status': r.status_code, 'revoked': gate.is_revoked()}}

    def attempt(label, method='post', path='/admin/kill-switch', **kw):
        # every attempt starts from a revoked agent, so a restore is blamed on the attempt that caused it.
        # re-engaging through the gate is harness setup, not part of the attack
        if not gate.is_revoked():
            gate.engage_kill_switch(actor='redteam-reset', reason='reset between attempts')
        try:
            r = client.request(method.upper(), path, **kw)
            status = r.status_code
        except Exception as e:                    # a request the client cannot even send did not restore anything
            status = 'client_error:' + type(e).__name__
        still = gate.is_revoked()
        attempts.append({'attempt': label, 'status': status, 'still_revoked': still})
        if not still:
            problems.append(f'RESTORED by: {label}')
        elif status == 200:
            problems.append(f'200 returned for: {label}')

    # 2. no credential, wrong credential, near-miss credentials
    attempt('no token', json=body)
    attempt('empty token', json=body, headers={'X-Admin-Token': ''})
    attempt('wrong token', json=body, headers={'X-Admin-Token': 'wrong'})
    for label, tok in (('token minus last char', ADMIN_TOKEN[:-1]), ('token plus a char', ADMIN_TOKEN + 'x'),
                       ('token uppercased', ADMIN_TOKEN.upper()), ('token with leading space', ' ' + ADMIN_TOKEN),
                       ('token with trailing space', ADMIN_TOKEN + ' ')):
        attempt(label, json=body, headers={'X-Admin-Token': tok})
    # same length as the token, last character replaced by a Cyrillic look-alike, sent as raw UTF-8 bytes
    attempt('token with non-ascii lookalike', json=body,
            headers={'X-Admin-Token': ADMIN_TOKEN[:-1].encode() + '\u0430'.encode('utf-8')})

    # 3. the right secret in the wrong place
    attempt('token in query string', json=body, params={'x_admin_token': ADMIN_TOKEN, 'token': ADMIN_TOKEN})
    attempt('token in body field', json={**body, 'token': ADMIN_TOKEN, 'admin': True, 'is_admin': True})
    attempt('token as bearer header', json=body, headers={'Authorization': 'Bearer ' + ADMIN_TOKEN})
    attempt('token in cookie', json=body, headers={'Cookie': 'X-Admin-Token=' + ADMIN_TOKEN})

    # 4. other verbs and path variants
    for verb in ('put', 'patch', 'delete', 'get'):
        attempt(f'{verb.upper()} on the route', method=verb, json=body)
    for path in ('/admin/kill-switch/', '//admin/kill-switch', '/ADMIN/kill-switch', '/admin/kill-switch/restore',
                 '/admin/kill-switch/revoke', '/admin/%6Bill-switch'):
        attempt(f'path variant {path}', path=path, json=body)

    # 5. a valid admin with a malformed body must not restore by accident
    for label, value in (('engaged as the string "false"', 'false'), ('engaged as 0', 0), ('engaged as null', None),
                         ('engaged as an empty list', []), ('engaged as "no"', 'no')):
        attempt(f'valid token, {label}', json={'engaged': value, 'reason': 'typo'}, headers=admin)
    attempt('valid token, engaged missing', json={'reason': 'typo'}, headers=admin)

    # 6. no second restore route exists
    paths = sorted(main.app.openapi().get('paths', {}))
    kill_paths = [p for p in paths if 'kill' in p.lower() or 'restore' in p.lower() or 'revoke' in p.lower()]
    if kill_paths != ['/admin/kill-switch']:
        problems.append(f'unexpected kill-switch or restore routes: {kill_paths}')

    # 7. while revoked, the service still refuses to work and the planner is not reached
    refused = client.post('/api/refund-requests', json=form()).json()
    if refused.get('status') != 'halted' or refused.get('outcome') != 'denied':
        problems.append(f'a refund was not halted while revoked: {refused.get("status")}/{refused.get("outcome")}')

    # 8. every refused attempt is audited, the secret is not, and the chain is intact
    audit = client.get('/admin/audit?limit=1000', headers=admin).json()
    kinds = [e['kind'] for e in audit['entries']]
    audited_refusals = kinds.count('admin_auth_denied')
    leaked = ADMIN_TOKEN in json.dumps(audit)
    if leaked:
        problems.append('the admin token appears in the audit trail')
    if not audit.get('chain_ok'):
        problems.append('the audit chain does not verify')
    if audited_refusals < 1:
        problems.append('no refused admin attempt was audited')

    # 9. control: a legitimate restore works, and refunds resume (so the chain is not vacuous)
    r = client.post('/admin/kill-switch', json=body, headers=admin)
    restored = (r.status_code == 200 and not gate.is_revoked())
    resumed = client.post('/api/refund-requests', json=form()).json()
    if not restored:
        problems.append('control failed: a legitimate admin restore did not work')
    elif resumed.get('outcome') != 'approved':
        problems.append(f'control failed: refunds did not resume ({resumed.get("outcome")})')

    return (not problems), {
        'problems': problems,
        'attempts_total': len(attempts),
        'attempts_that_restored': sum(1 for a in attempts if not a['still_revoked']),
        'status_codes': sorted({str(a['status']) for a in attempts}),
        'kill_related_routes': kill_paths,
        'refused_admin_attempts_audited': audited_refusals,
        'token_in_audit': leaked,
        'audit_chain_ok': audit.get('chain_ok'),
        'control_restore_worked': restored,
        'control_refund_after_restore': resumed.get('outcome'),
        'attempts': attempts,
    }


CHAINS = [
    ('RT-34', 'Unauthorized kill-switch restore', chain_rt34_unauthorized_restore),
]


def git_state():
    def run(*args):
        try:
            return subprocess.run(['git', '-C', ROOT, *args], capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return None
    return {'commit': run('rev-parse', 'HEAD'), 'dirty': bool(run('status', '--porcelain', '--', 'app'))}


def main():
    results = []
    for rid, name, fn in CHAINS:
        passed, detail = fn()
        results.append({'id': rid, 'name': name, 'control_held': bool(passed), 'detail': detail})
        print(f"{rid} {'PASS' if passed else 'FAIL'}  {name}")
        for p in detail.get('problems', []):
            print('     -', p)
    out_dir = os.path.join(ROOT, 'redteam', 'evidence')
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = os.path.join(out_dir, f'http_chains_{ts}.json')
    with open(path, 'w') as f:
        json.dump({'run_at': ts, 'target': 'app.main over HTTP (in-process TestClient)', 'git': git_state(),
                   'results': results}, f, indent=2, default=str)
    print(f'evidence: {path}')
    return 0 if all(r['control_held'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
