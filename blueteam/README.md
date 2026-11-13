# Blue team controls: refund limits and record access

Code-enforced controls that sit outside the LLM. Nothing in here reads a limit, a role or a
permission from a request, a prompt, an email or an uploaded policy.

| Control | Where | What it enforces |
|---|---|---|
| Limit control | `app/controls/limit_control.py` | $100 per refund, $500 per rolling 7 days across all customers, one refund per transaction, never more than the original charge, ownership, escalation to an admin |
| Access control | `app/controls/access_control.py` | Records are released only for the case at hand; full account numbers are never released |
| Kill switch | `app/controls/limit_control.py` | Anyone can stop the agent; only an admin can restore it |
| Audit trail | `app/controls/store.py` | One hash-chained row per decision, append-only |
| Service surface | `app/controls/gate.py` | The only module the service and the agents import |
| Admin HTTP routes | `app/controls/http.py` | `/admin/*`, guarded by `X-Admin-Token` |

State lives in one SQLite file (`logs/controls.db`, or `TRUSTISSUES_CONTROL_DB`), so the weekly
total, the replay guard and the kill switch survive a restart. Each decision is one
`BEGIN IMMEDIATE` transaction: check, write and audit commit together or not at all. If the
store cannot be written, the request is denied, the record goes to
`logs/controls.db.audit-fallback.jsonl`, and the HTTP caller gets a 503.

## Using it

Orchestrator and agents (Sargis):

```python
from app.controls import gate

scope, denial = gate.open_case(customer_id, transaction_id)   # ownership check; None + denial if it fails
records = gate.records_for(scope)                             # hand this to the Records agent
records.get_customer()        # {'allowed': True, 'record': {customer_id, email, account_last4}}
records.get_transaction()     # the case's own transaction only
records.recipient()           # the only address outbound mail may go to
records.filter_chunks(chunks) # retrieved chunks, limited to policy text and this case
decision = gate.request_refund(scope, amount, reason_code)    # approved | escalated | denied, with decision_id
gate.close_case(scope)
gate.is_revoked()             # check before any consequential step
gate.engage_kill_switch(actor='detector', reason='...')
```

A scope stops working after 30 minutes, after `close_case`, and while the kill switch is on.
`POST /api/refund-requests` goes form -> input scan -> orchestrator, which opens the case through the gate
(ownership check), runs the records and refunds agents, and gets the decision from limit control. The customer
sees the decision's `outcome`, `message` and `reference`, plus the case id and the step list (no steps on a denial,
so every denial looks the same). `gate.handle_refund_form` is still used for the audited denial when the ownership
check fails. Every denial looks the same from outside;
the reason is in the audit log. `app/main.py` calls `install_controls(app)` once to add the
admin routes and the error handlers.

Vector DB and retrieval (Vaishnavi): pass `records.retrieval_filter()` into the query, and run the
results through `records.filter_chunks(chunks)`. A chunk is kept only if it is tagged
`customer_id: None` (policy text) or with the case's customer, at the top level or under
`metadata`. Untagged chunks, chunks tagged with another `transaction_id`, and chunks containing
a full account number are dropped. Audit rows can be read with `gate.admin(token).read_audit()`;
each row has a `kind`, a `decision_id` and an `actor`.

Red team: `from app.controls.authority import RefundAuthority` has the same interface as the
stand-in `app/refund.py`. `blueteam/run_redteam.py` runs your harness unmodified against it.

Admin: set `TRUSTISSUES_ADMIN_TOKEN` (at least 16 printable ASCII characters) before starting
the server. Without it there is no admin. Refused admin attempts are audited.

```
GET  /admin/escalations
POST /admin/escalations/{id}/decision   {"approve": true, "note": "..."}
POST /admin/kill-switch                 {"engaged": false, "reason": "..."}
GET  /admin/audit
GET  /logs                              (now admin only, redacted)
```

## Running the checks

```bash
python3 -m unittest discover -s tests                 # controls only, standard library
.venv/bin/python -m unittest discover -s tests        # plus the HTTP tests (needs FastAPI)
python3 blueteam/run_retest.py --label after          # 24 checks; writes blueteam/evidence/retest_after_<ts>.json
python3 blueteam/run_retest.py --baseline-ref origin/redteam1 --label before
python3 blueteam/run_redteam.py --ref origin/redteam1
.venv/bin/python blueteam/run_redteam.py --ref origin/redteam-nagashree --python .venv/bin/python
```

Each evidence file records the git commit, a hash of `app/controls/*.py` and the Python version.

The pinned FastAPI and pydantic versions do not import on Python 3.13+. Use Python 3.10 to 3.12
for the server and the HTTP tests, with `httpx==0.27.2` for `TestClient`.

Findings and their retest status are in [FINDINGS.md](FINDINGS.md).

## Decisions that need the team

1. A request that would pass the weekly $500 is denied, not escalated. This matches RT-03 and
   RT-07; the proposal says over-limit requests escalate.
2. An admin can approve more than $100 for one refund, but admin approvals also count toward,
   and are bounded by, the weekly $500.
3. The test facade restores authority with `kill_switch(False)` and no credential because RT-05
   calls it that way. The service path requires the admin token.
4. Customer and transaction IDs must look like `C-<digits>` and `T-<digits>`.
5. Customer identity is self-asserted until there is a login.
