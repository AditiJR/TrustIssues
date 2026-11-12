"""Vector DB and retrieval (Vaishnavi, Blue).

embedder.py        text -> vector (offline hashing embedder by default)
vectorstore.py     SQLite vector DB with metadata pre-filtering and required tenant filters
policy_store.py    versioned refund policies: upload, scan, quarantine, approve, retrieve
customer_store.py  profiles, transactions and case history, scoped per customer

get_policy_store() and get_customer_store() return process-wide instances backed by one file,
TRUSTISSUES_RAG_DB if set, otherwise <repo>/logs/rag.db. The first call seeds the synthetic
policy and customers if the file is empty. Use ':memory:' for tests.
"""
import json
import os
import threading

from app.rag.customer_store import CustomerStore
from app.rag.policy_store import PolicyStore
from app.rag.vectorstore import VectorStore

SEED_DIR = os.path.join(os.path.dirname(__file__), 'seed')
DEFAULT_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'rag.db'))

_lock = threading.Lock()
_state = {}


def seed(policy_store, customer_store):
    """Idempotent: loads the seed policy and customers only where nothing is there yet."""
    if not policy_store.list_versions():
        with open(os.path.join(SEED_DIR, 'refund_policy.md')) as fh:
            policy_store.upload(fh.read(), title='TrustIssues Refund Policy', uploaded_by='seed', approve=True)
    with open(os.path.join(SEED_DIR, 'customers.json')) as fh:
        data = json.load(fh)
    if customer_store.source.writable:      # local fallback. With Blake's database, his store has the customers.
        for c in data['customers']:
            if customer_store.get_profile(c['customer_id']) is None:
                customer_store.upsert_customer(c['customer_id'], name=c['name'], email=c['email'],
                                               account_no=c['account_no'], actor='seed')
        for t in data['transactions']:
            customer_store.add_transaction(t['transaction_id'], t['customer_id'], t['amount_cents'],
                                           purchased_on=t['purchased_on'], item=t['item'])
    for c in data['cases']:
        if not customer_store.owns(c['customer_id'], c['transaction_id']):
            continue                        # e.g. C-3 and C-4 are not in Blake's seed data
        customer_store.add_case(c['customer_id'], c['transaction_id'], c['text'], case_id=c['case_id'],
                                reason=c['reason'], amount=c['amount'], status=c['status'], decision=c['decision'],
                                actor='seed')


def build(path=None, *, seed_data=True, detector=None, audit=None, source=None):
    """Fresh (vector_store, policy_store, customer_store) on one database."""
    vs = VectorStore(path or ':memory:')
    ps = PolicyStore(vs, detector=detector, audit=audit)
    cs = CustomerStore(vs, detector=detector, audit=audit, source=source)
    if seed_data:
        seed(ps, cs)
    return vs, ps, cs


def _get():
    path = os.environ.get('TRUSTISSUES_RAG_DB') or DEFAULT_DB
    with _lock:
        if _state.get('path') != path:
            _state.update(zip(('vs', 'ps', 'cs'), build(path)), path=path)
        return _state


def get_vector_store():
    return _get()['vs']


def get_policy_store():
    return _get()['ps']


def get_customer_store():
    return _get()['cs']
