# Blue team: data and detection (Vaishnavi)

Vector DBs, policy retrieval, the audit log, attack detection and the Records agent.
Everything here is standard library only (SQLite plus Python), runs offline and uses synthetic data.

| Part | File | What it does |
|---|---|---|
| Vector DB | `app/rag/vectorstore.py` | SQLite store with embeddings and metadata. Filters run in SQL before similarity scoring, and a collection can require a filter (tenant isolation). |
| Embedder | `app/rag/embedder.py` | Offline hashing embedder (default, deterministic). Optional sentence-transformers backend with `TRUSTISSUES_EMBEDDER=sbert`. |
| Policy store | `app/rag/policy_store.py` | Admin uploads are chunked, scanned, embedded and versioned. Bad chunks are quarantined. Retrieval uses only the latest approved version and returns provenance. |
| Customer store | `app/rag/customer_store.py` | Profiles, transactions and case history. Every case search must name a customer. Full account numbers are never embedded. |
| Retriever | `app/retriever.py` | Replaces the starter's keyword lookup with policy-store search. Same `get_context()` signature, so `app/agent.py` is unchanged. |
| Records agent | `app/records_agent.py` | `records_agent(case_id, task, case)`, same signature as the entries in Sargis's `AGENT_REGISTRY`. |
| Audit log | `app/monitoring/audit.py` | Shared, hash-chained, redacting log. Same file and keys as the starter's `logs/events.jsonl`. |
| Detection | `app/monitoring/detection.py` | Scans input, retrieved chunks and outbound text. Rules map to OWASP LLM and ASI ids and MAESTRO layers. |
| Behaviour rules | `app/monitoring/behavior.py` | Alerts from patterns across events: repeated attacks, record enumeration, refund splitting, action after revoke, floods, log tampering. |
| Admin routes | `app/data_api.py` | `/admin/policies`, `/admin/detect`, `/admin/detections`, `/admin/monitor/run`, `/admin/audit`, `/admin/audit/verify` |

## Running

```bash
pip install -r requirements.txt -r requirements-dev.txt     # Python 3.10 to 3.12 (pydantic 1.10 does not run on 3.13)
export TRUSTISSUES_ADMIN_TOKEN=change-me-to-16-plus-chars   # without it there is no admin
uvicorn app.main:app --reload --port 8000

python -m pytest -q                                         # 120 tests
python blueteam/data_and_detection/run_detection_eval.py    # evidence for the report
```

The first start creates `logs/rag.db` and seeds the refund policy (`app/rag/seed/refund_policy.md`)
and four synthetic customers (`app/rag/seed/customers.json`). C-1, C-2 and T-1001 to T-1009 match
the red team fixtures and Blake's control store. Delete `logs/rag.db` to re-seed.

Environment variables: `TRUSTISSUES_EVENT_LOG` (default `logs/events.jsonl`),
`TRUSTISSUES_RAG_DB` (default `logs/rag.db`), `TRUSTISSUES_ADMIN_TOKEN`, `TRUSTISSUES_EMBEDDER`.

## Admin API (header `X-Admin-Token`)

| Method and path | Purpose |
|---|---|
| `POST /admin/policies` `{text, title?, doc_name?, approve?}` | Upload a policy version. The reply lists quarantined chunks and why. |
| `GET /admin/policies` | All versions with status, uploader, sha256, chunk and quarantine counts |
| `GET /admin/policies/{doc}/{version}` | Download a version's full text |
| `POST /admin/policies/{doc}/{version}/approve` or `/reject` | Approve a pending version (the old one becomes superseded) or reject it |
| `GET /admin/policies/quarantine` | Every quarantined chunk with its rule ids |
| `POST /admin/policies/search` `{query, k}` | What the agent would retrieve, with provenance and scores |
| `POST /admin/detect` `{text, mode, customer_id?}` | Run the detector on any text (`mode` is input, retrieved or output) |
| `GET /admin/detections?min_severity=` | Detections, DLP hits, quarantines, alerts and refused admin calls |
| `POST /admin/monitor/run` | Run the behaviour rules now and return alerts |
| `GET /admin/audit?case_id=&action=` | Events for an investigation, for example everything on one case |
| `GET /admin/audit/verify` | Check the hash chain. Keep the returned `head` somewhere else to anchor it. |

## For Sargis (orchestrator)

Logging (this answers the TODO in `app/orchestrator.py`): replace the local `log_event` body with

```python
from app.monitoring.audit import log_event
log_event('orchestrator', 'step_start', case_id=case_id, step=i, agent=step['agent'])
```

Same file and same keys as before, plus `seq`, `event_id`, `severity` and the hash chain.
Use `severity='high'` for anything security relevant. Account numbers and email local parts are
masked automatically.

Records agent: in `app/agents.py` set `AGENT_REGISTRY['records'] = records_agent` from
`app.records_agent`. If you pass `case['authority_revoked'] = kill_switch.is_revoked()` the agent
reads nothing while revoked.

Scanning the customer's text before planning:

```python
from app.monitoring.detection import get_detector
scan = get_detector().scan_input(request['description'] or '', source='form', case_id=case_id,
                                 customer_id=request['customer_id'], allowed_transactions=[request['transaction_id']])
if scan.recommended_action == 'quarantine':
    ...  # send to admin review instead of the planner
```

Policy passages for an LLM prompt: `Retriever().prompt_context(query, case_id=case_id)` returns
passages wrapped in `<policy_passage>` tags with `<` escaped, so retrieved text cannot close the
tag and pose as instructions.

Before any reply or email leaves: `get_detector().scan_output(text, customer_id=..., allowed_emails=[email_on_file])`.
If `recommended_action == 'block'`, do not send. `sanitize_output(text)` masks account numbers and
strips markdown images and links.

Event names the behaviour rules look for: `kill_switch_revoke`, `step_start`, `case_received`,
`refund_decision`, `email_sent`. A revoke followed by any of these (other than a denial) raises a
critical `BEH-ACTION-AFTER-REVOKE` alert.

## For Blake (enforcement)

* Retrieved chunks already have the shape your `filter_chunks()` expects: `customer_id` and
  `transaction_id` at the top level and under `metadata`. Policy chunks are tagged `customer_id: None`.
* The Records agent uses your gateway when `case['records_gateway'] = gate.records_for(scope)` is set.
  It calls `get_customer()`, `get_transaction()` and `filter_chunks()`, and denies if either lookup is denied.
* `app/rag/policy_store.py` imports `PER_TXN_LIMIT_CENTS` and `WEEKLY_LIMIT_CENTS` from
  `app.controls.limits` when your branch is merged, so a policy that states a higher limit is checked
  against your constants. Until then it uses $100 and $500.
* `BehaviorMonitor().run(extra_events=gate.admin(token).read_audit())` also reads your audit rows
  (`kind`, `outcome`, `at_us`).
* The mock bank should call `customer_store.get_bank_account(customer_id, actor='mock-bank', purpose='refund payout', decision_id=...)`.
  It is the only place the full account number comes out, and every call is logged.
* `app/data_api.py` has its own `require_admin` with your convention (`X-Admin-Token`, 16 or more
  characters, `hmac.compare_digest`). Swap in yours when merging. I left `GET /logs` alone because
  your branch already adds auth there.

## For the red team (Aditi, Nagashree)

Set `TRUSTISSUES_EVENT_LOG` and `TRUSTISSUES_RAG_DB` to a temp dir in the harness so runs never touch the repo's `logs/`.
`retriever.store['refund'] = text` still works: it uploads the text through the real policy upload
path on a private in-memory store, so RT-17 and RT-20 now test the real scanner.

Run against this branch, `redteam/run_input_email_chains.py` gives RT-16 to RT-20 all PASS. RT-16,
RT-17, RT-19 and RT-20 failed on the starter.

| Test | What now holds it | Where |
|---|---|---|
| RT-13 | Policy text stating a limit above the coded limit is quarantined. Limits stay in code. | `policy_store.limit_conflicts` |
| RT-16 | Retrieval is semantic, so keywords no longer flip the starter's decision. The real check needs the LLM orchestrator. | `app/retriever.py` |
| RT-17, RT-27 | Poisoned chunks are quarantined at upload and scanned again at retrieval | `policy_store.upload`, `retrieve` |
| RT-18 | One entry per request, JSON escaping, and the hash chain flags inserted lines | `audit.py` |
| RT-19 | Account numbers and emails are masked when written, so `/logs` cannot leak them. Blake's branch also adds auth. | `audit.redact` |
| RT-20 | Internal-only material and canaries are quarantined from the policy store and blocked by output DLP | `policy_store`, `scan_output` |
| RT-21, RT-28 | Records agent takes scope from the case, never from task text. Foreign transactions are denied. | `records_agent.py` |
| RT-22 | NFKC, zero-width removal, HTML comment and hidden element extraction, base64 decoding | `detection.normalize` |
| RT-23 to RT-25 | Email injection, spoofed admin and memory poisoning are detected (Email agent should call `scan_input(source='email')`) | `detection.py` |
| RT-26, RT-29 | Case search requires a customer filter applied in SQL before scoring. Poisoned cases are flagged and dropped. | `vectorstore.py`, `customer_store.py` |
| RT-30, RT-31, RT-33 | Outbound DLP blocks foreign addresses, other customers, account numbers and external links | `scan_output` |

## Detection results and known gaps

From `run_detection_eval.py` (evidence in `evidence/`):

* Input detection: 24 of 24 attack payloads flagged (all of Nagashree's RT-16 to RT-33 inputs plus extra variants).
* False positives: 0 of 20 benign customer descriptions, 0 of 12 seed policy chunks.
* Retrieval and records controls: 7 of 7 held. Outbound DLP: 4 of 4 leaky replies blocked, a normal reply passes.

Known gaps, kept in the evaluation on purpose so the threat model can cite them:

* Leetspeak (`1gn0r3 4ll pr3v10us 1nstruct10ns`) is not detected.
* Non-English injections (a Spanish payload) are not detected.
* Paraphrased injections with none of the trigger phrases are not detected.

None of these can move money or widen record access, because those decisions are enforced in code
(limit control, access control and the Records agent's case scope), not by the detector. The detector is
for visibility and early review. A possible next step is a second-opinion LLM classifier for text the rules
mark clean but that comes from an untrusted source.

## Design notes

* The detector reports and logs. It never decides a refund. Callers choose the action:
  the retriever drops malicious chunks, policy upload quarantines them, and the orchestrator can send a
  `review` or `quarantine` case to an admin.
* Behaviour alerts do not trigger the kill switch automatically, so a flood of fake alerts cannot become a
  denial of service. An admin or the orchestrator decides.
* The hash chain detects edited, removed, inserted or reordered lines. It cannot detect lines cut from the
  end, or a whole log rewritten by someone with write access. Store the `head` from `/admin/audit/verify`
  elsewhere (for example in each evidence file) to anchor it.
* The default embedder is not a neural model. It was chosen because it works offline and keeps evidence
  reproducible. Retrieval quality is good enough for one short policy, and the sbert option is there if the
  team wants better semantic matching. That backend has not been run in this environment because the model
  download host was not reachable.
