"""Customer store: profiles, transactions and case history for the Records agent.

Two kinds of data, kept apart on purpose:

  Structured rows (SQLite tables)   customer profile incl. the full bank account number, and
                                    transactions. Used for exact lookups (ownership, last4).
  Vectors (collections 'cases' and 'profiles')
                                    case text and a short profile summary for RAG. Full account
                                    numbers are never embedded: summaries carry only the last 4
                                    digits, and case text is redacted before it is stored.

Tenant isolation (RT-26, RT-29): both vector collections require a customer_id filter on every
query. There is no method that searches across customers. Case text is scanned when it is stored
and again when it is retrieved, and anything that carries instructions to the agent is not
returned.

The full account number leaves this module only through get_bank_account(), which logs every
call. Only the refund payout (mock bank) should call it.
"""
import hashlib
import re
import uuid
from datetime import datetime, timezone

from app.monitoring.audit import get_audit_log, redact_text
from app.monitoring.detection import get_detector

CASES = 'cases'
PROFILES = 'profiles'
_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
MAX_CASE_TEXT = 4000

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers(
  customer_id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, account_no TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(
  transaction_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(customer_id),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0), purchased_on TEXT NOT NULL, item TEXT NOT NULL);
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _valid_id(value):
    return isinstance(value, str) and bool(_ID.match(value))


class CustomerStore:
    def __init__(self, vector_store, detector=None, audit=None):
        self.vs = vector_store
        self.detector = detector or get_detector()
        self._audit = audit
        self.vs.conn.executescript(SCHEMA)
        self.vs.require_filter_on(CASES, 'customer_id')
        self.vs.require_filter_on(PROFILES, 'customer_id')

    @property
    def audit(self):
        return self._audit or get_audit_log()

    # -------------------------------------------------------------- profiles
    def upsert_customer(self, customer_id, *, name, email, account_no, actor='admin'):
        if not _valid_id(customer_id):
            raise ValueError('bad customer_id')
        if not re.fullmatch(r'\d{6,17}', account_no or ''):
            raise ValueError('account_no must be 6 to 17 digits')
        now = _now()
        with self.vs._lock:
            existed = self.vs.conn.execute('SELECT 1 FROM customers WHERE customer_id = ?', (customer_id,)).fetchone()
            self.vs.conn.execute(
                'INSERT INTO customers VALUES (?,?,?,?,?,?) ON CONFLICT(customer_id) DO UPDATE SET '
                'name = excluded.name, email = excluded.email, account_no = excluded.account_no, updated_at = excluded.updated_at',
                (customer_id, name, email, account_no, now, now))
            summary = ('Customer %s (%s). Email on file %s. Bank account ending %s.'
                       % (customer_id, name, email, account_no[-4:]))
            existing = self.vs.find(PROFILES, {'customer_id': customer_id})
            if existing:
                self.vs.update(PROFILES, existing[0].doc_id, text=summary)
            else:
                self.vs.add(PROFILES, summary, {'doc_type': 'profile', 'customer_id': customer_id},
                            doc_id='PROFILE-' + customer_id)
        self.audit.log(actor, 'profile_updated' if existed else 'profile_created', customer_id=customer_id,
                       fields=['name', 'email', 'account_no'])
        return self.get_profile(customer_id)

    def update_contact(self, customer_id, *, name=None, email=None, actor='admin'):
        """Change non-financial profile fields. Bank details change only through upsert_customer (admin)."""
        p = self._raw(customer_id)
        if p is None:
            raise KeyError('no such customer')
        return self.upsert_customer(customer_id, name=name or p['name'], email=email or p['email'],
                                    account_no=p['account_no'], actor=actor)

    def _raw(self, customer_id):
        if not _valid_id(customer_id):
            return None
        row = self.vs.conn.execute('SELECT customer_id, name, email, account_no FROM customers WHERE customer_id = ?',
                                   (customer_id,)).fetchone()
        return dict(zip(['customer_id', 'name', 'email', 'account_no'], row)) if row else None

    def get_profile(self, customer_id):
        """Profile safe for agents: no full account number."""
        p = self._raw(customer_id)
        if p is None:
            return None
        return {'customer_id': p['customer_id'], 'name': p['name'], 'email': p['email'],
                'account_last4': p['account_no'][-4:]}

    def get_bank_account(self, customer_id, *, actor, purpose, case_id=None, decision_id=None):
        """Full account number for paying out an approved refund. Every call is logged."""
        p = self._raw(customer_id)
        self.audit.log(actor, 'bank_account_access', severity='medium', case_id=case_id, decision_id=decision_id,
                       customer_id=customer_id, purpose=str(purpose)[:80], found=p is not None)
        return p['account_no'] if p else None

    # -------------------------------------------------------------- transactions
    def add_transaction(self, transaction_id, customer_id, amount_cents, *, purchased_on, item):
        if not (_valid_id(transaction_id) and _valid_id(customer_id)):
            raise ValueError('bad id')
        with self.vs._lock:
            self.vs.conn.execute('INSERT OR IGNORE INTO transactions VALUES (?,?,?,?,?)',
                                 (transaction_id, customer_id, int(amount_cents), purchased_on, item))

    def get_transaction(self, transaction_id):
        if not _valid_id(transaction_id):
            return None
        row = self.vs.conn.execute('SELECT transaction_id, customer_id, amount_cents, purchased_on, item FROM transactions '
                                   'WHERE transaction_id = ?', (transaction_id,)).fetchone()
        return dict(zip(['transaction_id', 'customer_id', 'amount_cents', 'purchased_on', 'item'], row)) if row else None

    def owns(self, customer_id, transaction_id):
        t = self.get_transaction(transaction_id)
        return bool(t and t['customer_id'] == customer_id)

    def transactions_for(self, customer_id):
        rows = self.vs.conn.execute('SELECT transaction_id, amount_cents, purchased_on, item FROM transactions '
                                    'WHERE customer_id = ? ORDER BY transaction_id', (customer_id,)).fetchall()
        return [dict(zip(['transaction_id', 'amount_cents', 'purchased_on', 'item'], r)) for r in rows]

    # -------------------------------------------------------------- cases
    def add_case(self, customer_id, transaction_id, text, *, case_id=None, reason=None, amount=None, status='open',
                 decision=None, actor='records-agent'):
        """Store a case for RAG. Returns the case dict, or None if the transaction is not the customer's."""
        if not self.owns(customer_id, transaction_id):
            self.audit.log(actor, 'case_store_denied', severity='medium', case_id=case_id, customer_id=customer_id,
                           transaction_id=transaction_id, reason='transaction not owned by customer')
            return None
        case_id = case_id or 'CASE-' + uuid.uuid4().hex[:12]
        if not _valid_id(case_id):
            raise ValueError('bad case_id')
        existing = self.get_case(case_id, customer_id=customer_id)
        if existing:
            return existing
        text = (text or '').strip()[:MAX_CASE_TEXT] or '(no description)'
        scan = self.detector.scan_input(text, source='case_text', case_id=case_id, customer_id=customer_id,
                                        allowed_emails=[self._raw(customer_id)['email']],
                                        allowed_transactions=[transaction_id])
        body = 'Refund case %s for transaction %s. Reason: %s. Amount: %s.\n%s' % (
            case_id, transaction_id, reason or 'unspecified', amount if amount is not None else 'unspecified',
            redact_text(text))
        meta = {'doc_type': 'case', 'customer_id': customer_id, 'transaction_id': transaction_id, 'case_id': case_id,
                'status': status, 'reason': reason, 'decision': decision, 'flagged': not scan.clean, 'verdict': scan.verdict,
                'rule_ids': scan.rule_ids, 'created_at': _now()}
        self.vs.add(CASES, body, meta, doc_id=case_id)
        self.audit.log(actor, 'case_stored', case_id=case_id, customer_id=customer_id, transaction_id=transaction_id,
                       flagged=not scan.clean, verdict=scan.verdict,
                       text_sha256=hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest())
        return self.get_case(case_id, customer_id=customer_id)

    def get_case(self, case_id, *, customer_id):
        hits = self.vs.find(CASES, {'customer_id': customer_id, 'case_id': case_id})
        if not hits:
            return None
        h = hits[0]
        return {'case_id': case_id, 'text': h.text, **{k: h.metadata.get(k) for k in
                ('customer_id', 'transaction_id', 'status', 'reason', 'flagged', 'verdict', 'decision')}}

    def update_case(self, case_id, *, customer_id, status=None, decision=None, note=None, actor='records-agent'):
        """Update status/decision and append a note. Scoped: the case must belong to customer_id."""
        hits = self.vs.find(CASES, {'customer_id': customer_id, 'case_id': case_id})
        if not hits:
            self.audit.log(actor, 'case_update_denied', severity='medium', case_id=case_id, customer_id=customer_id)
            return None
        h = hits[0]
        meta, text = {}, None
        if status:
            meta['status'] = str(status)[:20]
        if decision:
            meta['decision'] = str(decision)[:40]
        if note:
            note = str(note)[:500]
            scan = self.detector.scan_input(note, source='case_note', case_id=case_id, customer_id=customer_id)
            if not scan.clean:
                meta['flagged'] = True
            text = h.text + '\nNote (%s): %s' % (actor, redact_text(note))
        self.vs.update(CASES, case_id, text=text, metadata=meta)
        self.audit.log(actor, 'case_updated', case_id=case_id, customer_id=customer_id, changed=sorted(meta) +
                       (['note'] if note else []))
        return self.get_case(case_id, customer_id=customer_id)

    def search_cases(self, query, *, customer_id, k=3, exclude_case_id=None, case_id=None, actor='records-agent'):
        """Semantic search over ONE customer's cases. Flagged or poisoned cases are not returned."""
        if not _valid_id(customer_id):
            return []
        hits = self.vs.query(CASES, query, k=k + 5, where={'customer_id': customer_id}, min_score=-1.0)
        out, dropped = [], []
        for h in hits:
            if h.doc_id == exclude_case_id:
                continue
            # belt and braces: the SQL filter already guarantees this
            if h.metadata.get('customer_id') != customer_id:
                dropped.append({'case_id': h.doc_id, 'why': 'wrong customer'})
                continue
            scan = self.detector.scan_retrieved(h.text, source='case_retrieval', case_id=case_id,
                                                customer_id=customer_id, extra={'retrieved_case': h.doc_id})
            if h.metadata.get('flagged') or scan.malicious:
                dropped.append({'case_id': h.doc_id, 'why': 'flagged content', 'rule_ids': scan.rule_ids})
                continue
            out.append(h.to_chunk())
            if len(out) >= k:
                break
        self.audit.log(actor, 'case_retrieval', case_id=case_id, customer_id=customer_id,
                       returned=[c['id'] for c in out], dropped=dropped,
                       severity='medium' if dropped else 'info')
        return out
