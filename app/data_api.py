"""HTTP routes for the policy store, detection and the audit log (all admin-only).

Mounted in app/main.py with app.include_router(router). Kept in its own module so it merges
cleanly with the routes Blake (app/controls/http.py) and Sargis (kill switch) add to main.py.

Admin auth uses the same convention as Blake's controls: header X-Admin-Token must equal
TRUSTISSUES_ADMIN_TOKEN (at least 16 printable ASCII characters). With no token configured,
there is no admin and every route here returns 403. Refused attempts are logged.
When Blake's branch is merged, require_admin below can be swapped for his.
"""
import hmac
import os
import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, conint, constr

from app.monitoring.audit import get_audit_log, SEVERITIES
from app.monitoring.behavior import BehaviorMonitor
from app.monitoring.detection import get_detector
from app.rag import get_policy_store
from app.records_agent import records_agent

MIN_TOKEN = 16


def require_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    expected = os.environ.get('TRUSTISSUES_ADMIN_TOKEN', '')
    ok = (len(expected) >= MIN_TOKEN and expected.isascii() and expected.isprintable()
          and isinstance(x_admin_token, str) and x_admin_token.isascii()
          and hmac.compare_digest(x_admin_token.encode('ascii'), expected.encode('ascii')))
    if not ok:
        get_audit_log().log('http', 'admin_auth_refused', severity='medium', path=request.url.path,
                            client=request.client.host if request.client else None,
                            token_present=x_admin_token is not None)
        raise HTTPException(status_code=403, detail='admin role required')
    return 'admin'


router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)], tags=['admin: data and detection'])


class PolicyUpload(BaseModel):
    text: constr(min_length=1, max_length=200_000)
    title: Optional[constr(max_length=120)] = None
    doc_name: constr(regex=r'^[a-z0-9][a-z0-9:._-]{0,63}$') = 'refund-policy'
    approve: bool = True


class PolicySearch(BaseModel):
    query: constr(min_length=1, max_length=1000)
    k: conint(ge=1, le=10) = 3


class RecordsLookup(BaseModel):
    customer_id: constr(strip_whitespace=True, min_length=1, max_length=64)
    transaction_id: constr(strip_whitespace=True, min_length=1, max_length=64)
    amount: constr(max_length=20) = '0.00'
    reason: constr(max_length=40) = 'damaged'
    description: constr(max_length=1000) = ''
    task: constr(max_length=1000) = 'Look up the customer and transaction for this case.'


class ScanRequest(BaseModel):
    text: constr(max_length=20_000)
    mode: Literal['input', 'retrieved', 'output'] = 'input'
    source: constr(max_length=40) = 'admin_test'
    customer_id: Optional[constr(max_length=64)] = None
    allowed_emails: list = []


# ------------------------------------------------------------------ policies
@router.post('/policies')
def upload_policy(body: PolicyUpload):
    """Chunk, scan, embed and store a new policy version. Quarantined chunks are listed in the reply."""
    try:
        return get_policy_store().upload(body.text, title=body.title, doc_name=body.doc_name, uploaded_by='admin',
                                         approve=body.approve)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get('/policies')
def list_policies():
    return get_policy_store().list_versions()


@router.get('/policies/quarantine')
def quarantined_chunks():
    return get_policy_store().quarantined_chunks()


@router.get('/policies/{doc_name}/{version}')
def download_policy(doc_name: str, version: int):
    doc = get_policy_store().get_document(version, doc_name=doc_name)
    if doc is None:
        raise HTTPException(status_code=404, detail='no such policy version')
    return doc


@router.post('/policies/{doc_name}/{version}/approve')
def approve_policy(doc_name: str, version: int):
    try:
        return get_policy_store().approve(version, doc_name=doc_name, approved_by='admin')
    except KeyError:
        raise HTTPException(status_code=404, detail='no such policy version')
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post('/policies/{doc_name}/{version}/reject')
def reject_policy(doc_name: str, version: int):
    if not get_policy_store().reject(version, doc_name=doc_name, rejected_by='admin'):
        raise HTTPException(status_code=409, detail='only a pending version can be rejected')
    return {'doc_name': doc_name, 'version': version, 'status': 'rejected'}


@router.post('/policies/search')
def search_policies(body: PolicySearch):
    """What the agent would retrieve for this query, with provenance and scores."""
    return get_policy_store().retrieve(body.query, k=body.k, actor='admin')


# ------------------------------------------------------------------ detection
@router.post('/detect')
def scan_text(body: ScanRequest):
    """Run the detector on a piece of text (for demos and red-team evidence). Logged like any scan."""
    d = get_detector()
    if body.mode == 'retrieved':
        res = d.scan_retrieved(body.text, source=body.source, customer_id=body.customer_id)
    elif body.mode == 'output':
        res = d.scan_output(body.text, customer_id=body.customer_id, allowed_emails=body.allowed_emails)
    else:
        res = d.scan_input(body.text, source=body.source, customer_id=body.customer_id,
                           allowed_emails=body.allowed_emails)
    return res.to_dict()


@router.get('/detections')
def detections(min_severity: Literal[SEVERITIES] = 'low', limit: conint(ge=1, le=1000) = 200):
    """Security-relevant events, newest last: detections, DLP hits, quarantines, alerts, refused admin calls."""
    actions = {'attack_detected', 'dlp_violation', 'policy_chunk_quarantined', 'security_alert', 'admin_auth_refused',
               'records_access_denied', 'case_store_denied'}
    events = get_audit_log().read(min_severity=min_severity)
    hits = [e for e in events if e.get('action') in actions
            or (isinstance(e.get('detection'), dict) and e['detection'].get('verdict') not in (None, 'clean'))]
    return hits[-limit:]


@router.post('/monitor/run')
def run_monitor():
    """Run the behaviour rules over the audit log and return current alerts."""
    return BehaviorMonitor().run()


# ------------------------------------------------------------------ records agent demo
@router.post('/records/lookup')
def records_lookup(body: RecordsLookup):
    """Run the Records agent on a test case and show exactly what it would hand to the other agents.
    The task field plays the planner's instruction, so injected text can be tried there."""
    case_id = 'CASE-DEMO-' + uuid.uuid4().hex[:8]
    req = body.dict()
    task = req.pop('task')
    return {'case_id': case_id, **records_agent(case_id, task, {'request': req})}


# ------------------------------------------------------------------ audit / investigation
@router.get('/audit')
def audit_events(case_id: Optional[str] = None, action: Optional[str] = None, min_severity: Optional[str] = None,
                 limit: conint(ge=1, le=5000) = 500):
    """Filtered audit events for an investigation, e.g. everything for one case."""
    return get_audit_log().read(case_id=case_id, action=action, min_severity=min_severity, limit=limit)


@router.get('/audit/verify')
def verify_audit():
    """Hash-chain check of the event log. Keep the returned 'head' somewhere else to anchor it."""
    return get_audit_log().verify()
