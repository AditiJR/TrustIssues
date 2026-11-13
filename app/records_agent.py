"""Records agent: access, storage and retrieval of customer records for one case.

Signature matches Sargis's AGENT_REGISTRY entries:

    records_agent(case_id, task, case) -> {'status': 'ok' | 'denied' | 'error', 'output': str, 'record': dict}

where case['request'] has customer_id, transaction_id, amount, reason and description.

Design choices (security first, the record lookup does not need an LLM):

  * Scope comes from the case, never from the task text. The planner's task string is written by
    an LLM that read customer text, so it may say "also look up C-2". It is scanned, logged, and
    used only as a search query, never to choose whose records to read (RT-21, RT-28).
  * Ownership is checked before anything is read: the transaction must belong to the customer.
  * Storage: the case is written to the customer store (RAG) on first sight, with its text scanned.
  * Retrieval: similar past cases come only from this customer's own cases (vector store
    pre-filter), and flagged or poisoned cases are dropped (RT-26, RT-29).
  * Minimum disclosure: the record has the email on file and the last 4 digits of the bank account.
    The full account number is never returned (RT-31, RT-33).
  * If Blake's access control is merged, pass his RecordsGateway as case['records_gateway'] and
    the agent uses it for the profile and transaction lookups, and runs his filter_chunks() over
    retrieved cases. Without it, the agent applies the same rules itself.
  * If the kill switch is engaged (case['authority_revoked'] is True, or the gateway denies), the
    agent reads nothing.
"""
from app.monitoring.audit import get_audit_log
from app.monitoring.detection import get_detector
from app.rag import get_customer_store

DEFAULT_QUERY = 'previous refund cases for this customer'
SAFE_FIELDS = ('customer_id', 'name', 'email', 'account_last4')


class RecordsAgent:
    def __init__(self, customer_store=None, detector=None, audit=None):
        self._cs = customer_store
        self._detector = detector
        self._audit = audit

    @property
    def cs(self):
        return self._cs or get_customer_store()

    @property
    def detector(self):
        return self._detector or get_detector()

    @property
    def audit(self):
        return self._audit or get_audit_log()

    def _deny(self, case_id, customer_id, reason, **extra):
        self.audit.log('records-agent', 'records_access_denied', severity='medium', case_id=case_id,
                       customer_id=customer_id, reason=reason, **extra)
        return {'status': 'denied', 'output': 'Records could not be retrieved for this case.', 'record': {}}

    def handle(self, case_id, task, case):
        req = (case or {}).get('request') or {}
        customer_id, txn_id = req.get('customer_id'), req.get('transaction_id')
        if case.get('authority_revoked'):
            return self._deny(case_id, customer_id, 'authority revoked')
        if not customer_id or not txn_id:
            return self._deny(case_id, customer_id, 'incomplete request')

        profile = self.cs.get_profile(customer_id)
        # 1. the task text from the planner is untrusted: scan it, use it only as a search query
        task_scan = self.detector.scan_input(task or '', source='planner_task', case_id=case_id,
                                             customer_id=customer_id,
                                             allowed_emails=[profile['email']] if profile else (),
                                             allowed_transactions=[txn_id])
        query = DEFAULT_QUERY if not task_scan.clean else (task or DEFAULT_QUERY)

        # 2. ownership and profile, through Blake's gateway when available
        gateway = case.get('records_gateway')
        if gateway is not None:
            cust = gateway.get_customer()
            txn_resp = gateway.get_transaction()
            if not cust.get('allowed') or not txn_resp.get('allowed'):
                return self._deny(case_id, customer_id, 'access control denied', via='gateway')
            profile = {**(profile or {}), **cust['record']}
            transaction = txn_resp.get('record') or self.cs.get_transaction(txn_id)
        else:
            if profile is None:
                return self._deny(case_id, customer_id, 'unknown customer')
            if not self.cs.owns(customer_id, txn_id):
                return self._deny(case_id, customer_id, 'transaction not owned by customer', transaction_id=txn_id)
            transaction = self.cs.get_transaction(txn_id)

        # 3. storage: make sure this case is in the store (scanned on the way in)
        stored = self.cs.add_case(customer_id, txn_id, req.get('description') or '', case_id=case_id,
                                  reason=req.get('reason'), amount=req.get('amount'), actor='records-agent')

        # 4. retrieval: this customer's own similar cases, poisoned ones dropped
        history = self.cs.search_cases(query, customer_id=customer_id, k=3, exclude_case_id=case_id, case_id=case_id)
        if gateway is not None and hasattr(gateway, 'filter_chunks'):
            history = gateway.filter_chunks(history)
        prior = [{'case_id': h['id'], 'transaction_id': h.get('transaction_id'),
                  'status': h['metadata'].get('status'), 'decision': h['metadata'].get('decision'),
                  'reason': h['metadata'].get('reason'), 'score': h['score']} for h in history]

        record = {
            'customer': {k: profile.get(k) for k in SAFE_FIELDS},
            'transaction': {'transaction_id': transaction['transaction_id'],
                            'amount': '%.2f' % (transaction['amount_cents'] / 100),
                            'purchased_on': transaction.get('purchased_on'), 'item': transaction.get('item'),
                            'owned_by_customer': True},
            'case_flagged': bool(stored and stored.get('flagged')),
            'task_flagged': not task_scan.clean,
            'prior_cases': prior,
            'prior_refunds_on_transaction': sum(1 for p in prior if p['transaction_id'] == txn_id
                                                and p['decision'] == 'approved'),
        }
        self.audit.log('records-agent', 'records_access', case_id=case_id, customer_id=customer_id,
                       transaction_id=txn_id, outcome='allowed',
                       fields_released=['customer.' + k for k in SAFE_FIELDS] + ['transaction', 'prior_cases'],
                       prior_case_ids=[p['case_id'] for p in prior], task_flagged=not task_scan.clean)
        output = ('Customer %s owns transaction %s (%s, $%s). %d prior case(s) on file.%s'
                  % (customer_id, txn_id, transaction.get('item', 'item'), record['transaction']['amount'], len(prior),
                     ' Case text was flagged for review.' if record['case_flagged'] else ''))
        return {'status': 'ok', 'output': output, 'record': record}


_default = RecordsAgent()


def records_agent(case_id, task, case):
    """Drop-in for AGENT_REGISTRY['records']."""
    try:
        return _default.handle(case_id, task, case)
    except Exception as exc:       # the orchestrator treats any non-ok status as a failed step
        get_audit_log().log('records-agent', 'records_agent_error', severity='medium', case_id=case_id,
                            error=type(exc).__name__)
        return {'status': 'error', 'output': 'Records lookup failed.', 'record': {}}
