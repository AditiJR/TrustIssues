"""Customers and transactions read from Blake's control database (team decision: single source of truth).

The fixture builds a SQLite file with the same customers and transactions tables and seed rows as
app/controls/store.py on Blake's branch, so this runs before his branch is merged.
"""
import json
import sqlite3

import pytest

from app.rag import build
from app.rag.records_source import ControlDBSource, LocalSource, pick_source
from app.records_agent import RecordsAgent

BLAKE_SCHEMA = """
CREATE TABLE customers(customer_id TEXT PRIMARY KEY, email TEXT NOT NULL, account_last4 TEXT NOT NULL,
                       account_no TEXT NOT NULL);
CREATE TABLE transactions(transaction_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
                          amount_cents INTEGER NOT NULL CHECK(amount_cents > 0));
"""
BLAKE_CUSTOMERS = [('C-1', 'c1.customer@shop.example.test', '4401', '000111222333'),
                   ('C-2', 'c2.customer@shop.example.test', '7702', '000444555666')]
BLAKE_TXNS = [('T-1001', 'C-1', 25000), ('T-1002', 'C-1', 8000), ('T-1003', 'C-2', 9000)] + \
             [('T-%d' % n, 'C-1', 10000) for n in range(1004, 1010)]


@pytest.fixture
def control_db(tmp_path, monkeypatch):
    path = tmp_path / 'controls.db'
    conn = sqlite3.connect(path)
    conn.executescript(BLAKE_SCHEMA)
    conn.executemany('INSERT INTO customers VALUES (?,?,?,?)', BLAKE_CUSTOMERS)
    conn.executemany('INSERT INTO transactions VALUES (?,?,?)', BLAKE_TXNS)
    conn.commit()
    conn.close()
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(path))
    monkeypatch.setenv('TRUSTISSUES_RECORDS_SOURCE', 'auto')
    return str(path)


@pytest.fixture
def cstores(control_db, audit, detector):
    return build(':memory:', detector=detector, audit=audit)


def test_auto_picks_control_db_when_present(control_db, monkeypatch):
    assert isinstance(pick_source(sqlite3.connect(':memory:')), ControlDBSource)
    monkeypatch.setenv('TRUSTISSUES_RECORDS_SOURCE', 'local')
    assert isinstance(pick_source(sqlite3.connect(':memory:')), LocalSource)


def test_auto_falls_back_to_local_without_it(isolated_paths, monkeypatch):
    import importlib.util
    if importlib.util.find_spec('app.controls') is not None:
        pytest.skip("Blake's code is merged, so auto always uses his database")
    monkeypatch.setenv('TRUSTISSUES_RECORDS_SOURCE', 'auto')
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(isolated_paths / 'missing.db'))
    assert isinstance(pick_source(sqlite3.connect(':memory:')), LocalSource)


def test_records_come_from_control_db(cstores):
    _, _, cs = cstores
    assert cs.source.name == 'control'
    assert cs.get_profile('C-1') == {'customer_id': 'C-1', 'name': None, 'email': 'c1.customer@shop.example.test',
                                     'account_last4': '4401'}
    assert cs.owns('C-1', 'T-1001') and not cs.owns('C-1', 'T-1003')
    assert cs.get_profile('C-3') is None and not cs.owns('C-3', 'T-2001')     # local-only seed data is not used
    assert [t['transaction_id'] for t in cs.transactions_for('C-2')] == ['T-1003']


def test_never_reads_or_returns_full_account_number(cstores, audit):
    _, _, cs = cstores
    assert cs.get_bank_account('C-1', actor='mock-bank', purpose='payout') is None
    assert audit.read(action='bank_account_access')[-1]['source'] == 'control'
    assert '000111222333' not in json.dumps([cs.get_profile('C-1'), cs.transactions_for('C-1')])


def test_this_side_cannot_write_blakes_data(cstores):
    _, _, cs = cstores
    with pytest.raises(PermissionError):
        cs.upsert_customer('C-9', name='x', email='x@y.test', account_no='123456789')
    with pytest.raises(PermissionError):
        cs.add_transaction('T-9', 'C-1', 100, purchased_on='2026-11-01', item='x')
    with pytest.raises(sqlite3.OperationalError):
        cs.source._db().execute("UPDATE customers SET email = 'evil@x.test'")


def test_seed_cases_only_for_customers_in_control_db(cstores):
    vs, _, cs = cstores
    assert cs.get_case('CASE-H0001', customer_id='C-1') and cs.get_case('CASE-H0002', customer_id='C-2')
    assert vs.count('cases', {'customer_id': 'C-3'}) == 0


def test_records_agent_on_control_db(cstores, detector, audit):
    agent = RecordsAgent(customer_store=cstores[2], detector=detector, audit=audit)
    out = agent.handle('CASE-K1', 'records', {'request': {'customer_id': 'C-1', 'transaction_id': 'T-1002',
                                                          'amount': '40.00', 'reason': 'damaged',
                                                          'description': 'mug cracked'}})
    assert out['status'] == 'ok'
    assert out['record']['customer']['account_last4'] == '4401'
    assert out['record']['transaction']['amount'] == '80.00'
    denied = agent.handle('CASE-K2', 'records', {'request': {'customer_id': 'C-1', 'transaction_id': 'T-1003'}})
    assert denied['status'] == 'denied'
