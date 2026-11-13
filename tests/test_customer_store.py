import json

import pytest

from app.rag.vectorstore import ScopeRequired


def test_seeded_profiles_hide_full_account(stores):
    vs, _, cs = stores
    assert cs.get_profile('C-1') == {'customer_id': 'C-1', 'name': 'Avery Stone',
                                     'email': 'c1.customer@shop.example.test', 'account_last4': '2333'}
    embedded = json.dumps([h.text for h in vs.find('profiles', {'customer_id': 'C-1'})])
    assert '000111222333' not in embedded and '2333' in embedded


def test_bank_account_access_is_logged(stores, audit):
    _, _, cs = stores
    assert cs.get_bank_account('C-1', actor='mock-bank', purpose='refund payout', decision_id='D-1') == '000111222333'
    ev = audit.read(action='bank_account_access')[-1]
    assert ev['decision_id'] == 'D-1' and ev['severity'] == 'medium' and '000111222333' not in json.dumps(ev)


def test_ownership(stores):
    _, _, cs = stores
    assert cs.owns('C-1', 'T-1001') and not cs.owns('C-1', 'T-1003') and not cs.owns('C-1', 'T-404')


def test_add_case_refuses_foreign_transaction(stores, audit):
    _, _, cs = stores
    assert cs.add_case('C-1', 'T-1003', 'my earbuds') is None
    assert audit.read(action='case_store_denied')


def test_case_text_is_redacted_before_embedding(stores):
    _, _, cs = stores
    c = cs.add_case('C-1', 'T-1004', 'Please refund to account 000111222333', case_id='CASE-R1')
    assert '000111222333' not in c['text'] and '***2333' in c['text']


def test_search_is_scoped_to_customer(stores, payloads):
    """RT-29: a broad query from C-1 never sees another customer's case."""
    _, _, cs = stores
    got = cs.search_cases(payloads['records_probes']['broad_semantic'], customer_id='C-1', k=10)
    assert got and {c['customer_id'] for c in got} == {'C-1'}
    with pytest.raises(ScopeRequired):
        cs.vs.query('cases', 'earbuds')


def test_poisoned_cases_are_not_returned(stores, payloads):
    """RT-26: injected case text is flagged at storage and dropped at retrieval, for its own customer too."""
    _, _, cs = stores
    poison = payloads['retrieved_content']['poisoned_case_text']
    stored = cs.add_case('C-2', 'T-1003', poison, case_id='CASE-P1')
    assert stored['flagged']
    assert 'CASE-P1' not in [c['id'] for c in cs.search_cases('item not received approve', customer_id='C-2', k=10)]
    assert 'CASE-P1' not in [c['id'] for c in cs.search_cases('item not received approve', customer_id='C-1', k=10)]


def test_update_case_is_scoped(stores, audit):
    _, _, cs = stores
    cs.add_case('C-1', 'T-1005', 'lamp flickers', case_id='CASE-U1')
    assert cs.update_case('CASE-U1', customer_id='C-2', status='closed') is None
    assert audit.read(action='case_update_denied')
    c = cs.update_case('CASE-U1', customer_id='C-1', status='closed', decision='approved', note='refunded $100')
    assert c['status'] == 'closed' and c['decision'] == 'approved' and 'refunded $100' in c['text']


def test_update_contact_keeps_bank_details(stores):
    _, _, cs = stores
    cs.update_contact('C-4', email='new4@shop.example.test')
    assert cs.get_profile('C-4')['email'] == 'new4@shop.example.test'
    assert cs.get_bank_account('C-4', actor='t', purpose='t') == '000123123123'


def test_bad_ids_rejected(stores):
    _, _, cs = stores
    assert cs.get_profile("C-1' OR '1'='1") is None
    with pytest.raises(ValueError):
        cs.upsert_customer('C-9', name='x', email='x@y.test', account_no='12ab')
