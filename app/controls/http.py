"""FastAPI glue for the controls. The only module in app/controls that imports FastAPI.

    from app.controls.http import install_controls, refund_response, require_admin, redact
    install_controls(app)                                   # /admin/* routes and error handlers
    @app.get('/logs', dependencies=[Depends(require_admin)])

The admin token is sent in the X-Admin-Token header and compared with TRUSTISSUES_ADMIN_TOKEN.
"""
import re
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, StrictBool, constr

from app.controls import gate
from app.controls.store import clean_text

_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_LONG_DIGITS = re.compile(r'\d{8,}')
_AUDIT_STRUCTURAL = ('seq', 'at_us', 'kind', 'decision_id', 'escalation_id', 'case_id')


def admin_console(request: Request, x_admin_token: Optional[str] = Header(None)):
    console = gate.admin(x_admin_token, purpose='%s %s' % (request.method, request.url.path))
    if console is None:
        raise HTTPException(status_code=403, detail='admin role required')
    return console


def require_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    """Dependency for endpoints that only need the check, not the console."""
    admin_console(request, x_admin_token)


def redact(value):
    """Mask e-mail addresses and digit runs of 8 or more, recursively, in strings, dict keys and integers.
    Strings are also made valid UTF-8 so one bad character cannot break the response. Used on log reads.
    This is pattern matching, not a guarantee: numbers split by spaces or dashes are not caught."""
    if isinstance(value, str):
        text = clean_text(value, len(value))
        return _LONG_DIGITS.sub('[redacted-number]', _EMAIL.sub('[redacted-email]', text))
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return '[redacted-number]' if abs(value) >= 10 ** 7 else value
    if isinstance(value, dict):
        return {(redact(k) if isinstance(k, str) else k): redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def redact_audit_row(row):
    """Redact an audit row but keep the ids and sequence fields intact so references can be looked up."""
    return {k: (v if k in _AUDIT_STRUCTURAL else redact(v)) for k, v in row.items()}


def refund_response(decision):
    """Customer-facing body for a refund decision. 503 if the decision could not be written to the audit table."""
    if decision.get('reason') == gate.UNAVAILABLE:
        raise HTTPException(status_code=503, detail='try again later')
    return gate.public_view(decision)


class EscalationDecision(BaseModel):
    approve: StrictBool
    note: constr(max_length=200) = ''


class KillSwitch(BaseModel):
    engaged: StrictBool
    reason: constr(max_length=200) = ''


router = APIRouter(prefix='/admin', tags=['admin'])


@router.get('/escalations')
def list_escalations(status: str = 'pending', console=Depends(admin_console)):
    rows = console.list_escalations(status)
    if rows is None:
        raise HTTPException(status_code=400, detail='unknown status')
    return rows


@router.post('/escalations/{escalation_id}/decision')
def decide_escalation(escalation_id: str, body: EscalationDecision, console=Depends(admin_console)):
    return console.decide_escalation(escalation_id, body.approve, body.note)


@router.post('/kill-switch')
def kill_switch(body: KillSwitch, console=Depends(admin_console)):
    if body.engaged:
        return console.engage_kill_switch(body.reason)
    return console.restore_authority(body.reason)


@router.get('/audit')
def read_audit(after_seq: int = 0, limit: int = 200, console=Depends(admin_console)):
    rows = [r for r in console.read_audit() if r['seq'] > after_seq][:max(1, min(limit, 1000))]
    return {'chain_ok': console.verify_audit_chain(), 'head': console.audit_head(),
            'entries': [redact_audit_row(r) for r in rows]}


async def _store_unavailable(request, exc):
    return JSONResponse(status_code=503, content={'detail': 'controls unavailable, try again later'})


async def _validation_error(request, exc):
    # Only where and what, never the rejected value: echoing it back can fail to serialise (NaN) and leaks input.
    errors = [{'loc': [str(p) for p in e.get('loc', ())], 'msg': str(e.get('msg', '')), 'type': str(e.get('type', ''))}
              for e in exc.errors()]
    return JSONResponse(status_code=422, content={'detail': errors})


def install_controls(app):
    """Add the /admin routes and the error handlers the controls rely on."""
    app.include_router(router)
    app.add_exception_handler(sqlite3.Error, _store_unavailable)
    app.add_exception_handler(RequestValidationError, _validation_error)
