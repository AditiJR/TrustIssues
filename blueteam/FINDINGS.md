# Findings register: limit control and record access

Status of every finding against the refund-limit and record-access controls, with the check that
retests it. Check IDs refer to `blueteam/run_retest.py`; HTTP tests are in
`tests/test_http_controls.py`. Evidence is in `blueteam/evidence/`:

- `retest_before_*.json`: the checks run against the red team's stand-in `app/refund.py`
  (`origin/redteam1`).
- `retest_after_*.json`: the same checks run against `app/controls`.
- `redteam_run_*.json` and `redteam_<commit>_*.json`: the red team's own harnesses, unmodified,
  run against this tree.

## 1. Red-team tests

| Test | What it attacks | Result against this tree |
|---|---|---|
| RT-02 to RT-08 | Per-refund cap, weekly cap, replay, kill switch, cross-customer refund, window rollover, audit completeness | Pass, now against the real limit control instead of the stand-in |
| RT-19 | Reading another customer's submission through `GET /logs` | Fixed. `/logs` needs the admin token and is redacted |
| RT-16, RT-17, RT-20 | Prompt injection and note leakage in the starter agent and retriever | Still failing. Not in limit control or access control; needs the real agent and retrieval path |
| RT-09 to RT-15, RT-21 to RT-33 | Planned or blocked on components that do not exist yet | The controls they depend on are covered by the checks in section 2 until the red chains exist |

## 2. Weaknesses found in the stand-in, fixed in `app/controls`

| ID | Weakness in the stand-in | Fix | Retest |
|---|---|---|---|
| F01 | Concurrent requests could refund one transaction twice and pass the weekly cap | One lock and one `BEGIN IMMEDIATE` transaction per decision; unique index and trigger in the schema as a second layer | BT-F01a, BT-F01b |
| F02 | A request already in flight completed after the kill switch | Revocation is read inside the committing transaction, under the same lock as the switch | BT-F02 |
| F03 | Amounts such as `1e26` raised an exception with no audit entry | Strict amount and ID parsing; every failure path returns an audited denial | BT-F03, BT-P02 |
| F04 | Weekly total, replay guard and kill switch were lost on restart | State is in SQLite | BT-F04 |
| F05 | Any caller could switch the kill switch back off | Restoring needs an admin principal; the service path needs the admin token | BT-F05, BT-GATE01 |
| F06 | Limits and ledger were module globals any caller could change | Limits are constants and also schema constraints; the ledger is in the store | BT-F06 |
| F07 | Audit log was a mutable list with no decision ID | Append-only, hash-chained table; every outcome carries a decision ID | BT-F07, BT-AUD01 |
| F08 | A failure between issuing and logging left an unaudited refund | Refund row and audit row commit together | BT-F08 |
| F09 | The clock was a public attribute; a naive datetime crashed | Clock is private and validated; a bad clock is a denial | BT-F09 |
| F10 | Escalation was a dead end with no admin decision | Persisted escalations, admin approve or deny, final | BT-F10, BT-ESC01 |
| F13 | No caller identity, case binding, reason field or bank seam | Case scope, reason codes, bank callable with reserve and settle | BT-AC01 to BT-AC04, BT-BANK01 |

Two reported items were not treated as weaknesses: one refund per transaction (so no second
partial refund), and loose typing of identifiers, which strict parsing now covers anyway.

## 3. Found in our own review of `app/controls`, fixed

| ID | Severity | Finding | Fix | Retest |
|---|---|---|---|---|
| B01 | High | A kill-switch reason containing an unpaired surrogate raised mid-transaction and left the store wedged: the switch could not be engaged afterwards | All free text is normalised before it is stored; every write uses a transaction that rolls back on error; a stop also sets an in-process flag before the write | BT-FAIL01, HTTP test `hostile_text` |
| B02 | Medium | `filter_chunks` checked only the customer tag: other transactions and chunks carrying a full account number got through | Transaction tag checked; chunks with an `account_no` field or any customer's full account number are dropped; conflicting tags are dropped | BT-AC03 |
| B03 | Medium | With the store locked by another writer, a denial was returned with a reference that was in no log, and the kill switch raised | Fallback audit file; the caller gets `control store unavailable` (HTTP 503); the stop flag holds in the process | BT-FAIL02, HTTP test `503` |
| B04 | Medium | `"reason": NaN` in the refund form gave a 500 | Validation errors no longer echo the rejected value | HTTP test `odd_request_bodies` |
| B05 | Medium | An admin note with an unpaired surrogate made `GET /admin/audit` fail permanently | Same normalisation as B01; the read path is tolerant | BT-FAIL01, HTTP test `hostile_text` |
| B06 | Low | Bank path released the reservation on any error, so a paid refund could be paid again | After the bank has been called, an error leaves the reservation in place; the idempotency key is per transaction | BT-BANK01 |
| B07 | Low | Admin token: no minimum length; non-ASCII handling was loose | At least 16 printable ASCII characters, exact comparison | BT-GATE01, HTTP test `admin_token` |
| B08 | Low | Refused admin attempts left no audit row | Audited as `admin_auth_denied`, without the token | BT-AUD01, BT-GATE01 |
| B09 | Low | Audit view redaction mangled decision IDs | IDs and sequence fields are not redacted | HTTP test `audit_view` |
| B10 | Low | `close_case` logged a close whether or not anything was closed | Outcome recorded from the row count | BT-AC04 |
| B11 | Low | Several checks could pass without testing their control | Checks rewritten with explicit assertions and a deterministic overlap; verified by breaking each control in a copy and confirming a check fails | section 5 |

## 4. Known limits, not fixed

| Limit | Why it stands | What would close it |
|---|---|---|
| Customer identity is self-asserted | There is no login yet | Authentication; then bind the case to the session |
| Anything running inside the server process can reach the store | Python has no in-process boundary | Run the controls as a separate service |
| The 7-day window and the 30-minute scope follow the system clock | A clock set forward empties the window | A monotonic or external time source |
| Deleting `logs/controls.db` resets the ledger, the kill switch and the audit log | The file is the only copy | Back up the file; compare the audit head with the copy in each evidence file |
| The hash chain cannot detect a log rewritten from scratch or cut at the end | Nothing outside the file anchors it | Publish the head hash elsewhere; `GET /admin/audit` returns it |
| Log redaction is pattern based | Numbers split by spaces or dashes are not caught | Do not log customer free text |
| Any code holding `app.controls.gate` can open a case for any valid customer and transaction pair | The orchestrator is trusted to open cases | Give agents only the `RecordsGateway` and a bound refund function, never the module |
| The actor name on a kill-switch row is a label | Only `by_admin` is verified | Authenticated agent identities |
| A refund in `reserved` state after an unknown bank outcome needs manual reconciliation | No bank exists yet | A reconciliation step when the mock bank is built |

## 5. How the checks themselves were checked

Each control was broken on purpose in a copy of the tree, one change at a time (for example:
remove the lock, drop the weekly check, return `account_no`, skip the ownership check, stop
writing one kind of audit row, accept a token prefix). A check counts as effective only if at
least one test fails when its control is broken. 81 such changes were tried and all 81 are
caught; two were missed on the first pass (the unique index behind the replay rule, and the
revocation re-check before the bank call) and got their own checks. The list of changes and
results is in `blueteam/evidence/mutation_sweep.txt`.
