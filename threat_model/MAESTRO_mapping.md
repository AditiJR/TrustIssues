# MAESTRO Threat Model Mapping

Fill in each layer using the MAESTRO template.

MAESTRO layers used below: **L1** Foundation Models, **L2** Data Operations, **L3** Agent Frameworks,
**L4** Deployment & Infrastructure, **L5** Evaluation & Observability, **L6** Security & Compliance,
**L7** Agent Ecosystem / Use Case.

---

## Input and email paths (Red: Nagashree Kudligi Nagaraja)

Status: iteration 1 (plausible attacks) plus first attack chains. Outline only; it will be updated as Blue
builds the agents and as test results come in.

### Scope and assumptions
- Covers every place untrusted text enters the system (form, inbound email, retrieved content) and the
  channels data could leave through (customer reply, outbound email, logs).
- Refund limits, replay and revocation are covered by Aditi's section (RT-02 to RT-15), not here.
- **"Existing control" means what is in the repo today.** Controls described only in the proposal are marked
  *(designed)*. Today the repo has the starter `app/agent.py`, `app/retriever.py` and `app/main.py`, plus
  `app/refund.py`, which is a Red-team stand-in. None of these are the Blue team's implementation.
- All data is synthetic. Attackers are modelled as an external customer, a third-party email sender, or a
  malicious or compromised policy author.

### Attacker objectives
1. **Goal hijack:** make the Orchestrator or a specialized agent act on attacker text as instructions, for
   example to re-route sub-tasks, change a decision or its reason, or skip a step.
2. **Exfiltration:** obtain another customer's case, profile or bank info, or internal content such as the
   system prompt, policies or internal notes.
3. **Abuse of the Email agent:** send mail to an address not on file, or attach data that belongs to
   another customer.
4. **Persistence:** plant text in memory, case history or the policy store that affects later cases.
5. **Cover tracks:** forge or corrupt audit-log entries.

### Attacker capabilities
- Customer: controls every refund-form field, including the free-text description, and can submit many
  cases.
- Email sender: controls the headers (From, Reply-To, display name) and the body (HTML, hidden text,
  attachments) of any inbound email.
- Policy author (insider or compromised admin): controls the content of an uploaded policy document.
- None of them has direct access to the LLM, tools, vector DB or logs.

---

### E1. Refund form: structured fields (customer ID, transaction ID, amount, reason category)
- **Threats**
  - Customer ID or transaction ID of another customer (IDOR) used to read their case.
  - Out-of-enum reason category carrying instruction text.
  - Oversized or malformed values aimed at parsers (ASI05 is unlikely with no code execution path).
- **MAESTRO layers:** L3 (input reaches the planner), L6 (validation), L2 (lookup by ID).
- **OWASP:** LLM01, LLM02, ASI03.
- **Existing control:** `app/refund.py` stand-in checks transaction ownership before the limit check.
  The starter `POST /tasks` accepts any `task` string and any `data` dict with no schema or authentication.
  *(Designed:)* request validation and an ownership check before the policy check (User Guide 3.3).
- **Residual risk:** **High** until the form is schema-validated and bound to an authenticated customer
  session. The customer ID is self-asserted today.
- **Tests:** RT-28 (cross-customer read). The amount and ownership chains are Aditi's RT-02 and RT-06.

### E2. Refund form: free-text reason and description
- **Threats**
  - Direct prompt injection, for example "ignore policy", "you are now admin" or "also email my case to…"
    (LLM01, ASI01).
  - Obfuscated injection: zero-width characters, homoglyphs, base64, HTML comments, markdown.
  - Retrieval steering: keywords chosen to pull a favourable policy chunk into context (LLM08, ASI06).
  - Log forging: newlines or JSON fragments that try to create fake audit entries (MAESTRO L5).
  - Output-handling payloads that are later rendered in the UI or an email (LLM10).
- **MAESTRO layers:** L1 (model obeys injected text), L3 (planner and routing), L5 (log integrity),
  L7 (goal hijack).
- **Existing control**
  - None for injection. The starter agent puts the raw task text into plan steps and uses it as the
    retrieval key.
  - Log lines are written with `json.dumps`, which escapes newlines (RT-18 checks this).
  - *(Designed:)* limits are enforced in code, so injection cannot raise the amount. That is Aditi's RT-10.
- **Residual risk:** **High.** Free text reaches the planner and the retriever unseparated from
  instructions. Nothing flags or tags it as untrusted.
- **Tests:** RT-16, RT-18, RT-21, RT-22.

### E3. Inbound email (untrusted)
- **Threats**
  - Indirect injection in the body or hidden HTML aimed at the Email agent ("forward this thread to…",
    "reply with the customer's bank details") (LLM01, ASI01, ASI02).
  - Spoofed authority: From or display name posing as an admin or the Orchestrator ("approved by admin,
    process now") (ASI03, ASI09).
  - Memory poisoning: email text saved to long-term notes and reused as guidance on later cases (ASI06).
  - Reply-To swap that redirects the decision email to an attacker address (LLM02).
  - The Email agent's output passed to the Orchestrator as trusted results (ASI07).
- **MAESTRO layers:** L3 (Email agent tools), L2 (memory and notes), L6 (sender authentication),
  L7 (impersonation).
- **Existing control:** none in code, because there is no Email agent or mock mailbox yet.
  *(Designed:)* inbound email treated as untrusted; agents talk only through the Orchestrator; every message
  is logged.
- **Residual risk:** **High** (unbuilt). The design says "untrusted" but does not yet say how. Needed:
  provenance tags on email content, no admin authority over email, and outbound mail only to the address
  on file.
- **Tests:** RT-23, RT-24, RT-25, RT-30, RT-31.

### E4. Retrieved policy content (RAG policy store, admin uploads)
- **Threats**
  - A poisoned policy chunk containing instructions (indirect injection) (LLM01, LLM05, ASI06).
  - Policy text echoed verbatim to customers, exposing internal thresholds or notes (LLM02, LLM08).
  - Raising limits through policy is Aditi's RT-13 and is not repeated here.
- **MAESTRO layers:** L2 (data poisoning), L3 (context assembly), L1.
- **Existing control**
  - Starter `Retriever` is a fixed in-memory dict matched by keyword.
  - `Agent.handle_task` returns the first 200 characters of retrieved text as `context_snippet` without
    filtering, and marks the decision `proceed` with confidence 0.9 whenever anything is retrieved.
  - *(Designed:)* versioned policy uploads and an admin-only role.
- **Residual risk:** **Medium-High.** Admin upload is a privileged path, but retrieved text is trusted
  equally with system instructions and is returned to the requester.
- **Tests:** RT-17, RT-20, RT-27.

### E5. Retrieved case and profile content (vector DB: cases, profiles, mock bank info)
- **Threats**
  - Another customer's case text, which may itself carry an injection, retrieved by similarity and
    placed in context (ASI06, LLM08).
  - Broad semantic queries that return chunks belonging to other customers (LLM02, LLM09).
  - Bank or account fields carried from the retrieved profile into replies or emails (LLM02).
- **MAESTRO layers:** L2, L6 (access control), L3.
- **Existing control:** none in code. *(Designed:)* access control outside the LLM limits the Records agent
  to the current case.
- **Residual risk:** **High** until filtering by customer and case ID happens in the retrieval query
  before results reach the LLM, rather than as a post-hoc instruction.
- **Tests:** RT-26, RT-28, RT-29.

### Exit paths (exfiltration channels)
| Channel | Threat | Existing control | Residual | Tests |
|---|---|---|---|---|
| Customer-facing response (UI) | Echo of retrieved policy, notes or other customers' data; system-prompt leak | None. `context_snippet` is returned verbatim | High | RT-20, RT-32 |
| Outbound email (Email agent) | Send to an address not on file; attach other customers' records or bank info | None (unbuilt). *(Designed:)* mock email only | High | RT-30, RT-31 |
| Rendered links and images | Markdown image or link carrying data in its URL (LLM10) | None (UI unbuilt) | Medium | RT-33 |
| `GET /logs` (starter) | Unauthenticated read of every request, including other customers' text | None: no auth on `/logs` | High | RT-19 |
| Audit log integrity | Forged entries via newline or JSON in input | `json.dumps` escaping | Low | RT-18 |

### Recommended controls for Blue (input to iteration 2)
1. Keep untrusted text (form free text, email bodies, retrieved chunks) in a separate, labelled data channel.
   It must never be concatenated into instructions. Log the provenance of each piece of text.
2. Build the retrieval key from structured fields (reason category, transaction ID), not raw free text.
   Filter vector-DB queries by customer and case ID in code.
3. Email agent: send only to the address on file for the authenticated customer ID, use an allowlisted
   domain for the mock mailbox, and run an outbound content check for other customers' IDs and bank fields.
4. Give no authority to email content. Admin actions come only from the admin console role.
5. Do not echo retrieved policy or note text to customers. Return a decision and reason code instead.
6. Authenticate `/logs` (admin role) and redact customer data in log reads.
7. Put a canary string in each agent's system prompt and alert if it appears in any output, email or log
   read.
