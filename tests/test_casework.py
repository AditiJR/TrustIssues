"""case queue, mailbox and decision records. runs on sqlite, and on postgres too when TRUSTISSUES_TEST_PG_URL is set."""
import os
import sqlite3
import uuid

import pytest

from app.casework.store import CaseworkStore, db_path

PG_URL = os.environ.get('TRUSTISSUES_TEST_PG_URL')


@pytest.fixture(params=['sqlite'] + (['postgres'] if PG_URL else []))
def store(request, tmp_path):
    s = CaseworkStore(str(tmp_path / 'casework.db') if request.param == 'sqlite' else PG_URL)
    yield s
    s.close()


def _case():
    # postgres keeps rows between runs and the tables are append-only, so every test uses fresh ids
    return 'case-' + uuid.uuid4().hex[:12]


def _write_refused():
    import app.controls.pg as pg
    return (sqlite3.Error,) + ((pg.psycopg.Error,) if pg.psycopg is not None else ())


def test_enqueue_is_once_per_case(store):
    cid = _case()
    assert store.enqueue(cid, 'CASE-1', 'C-1', 'T-1002', 8000, 'damaged') is True
    assert store.enqueue(cid, 'CASE-1', 'C-1', 'T-1002', 8000, 'damaged') is False
    [row] = store.queue(cid)
    assert row['status'] == 'queued' and row['amount_cents'] == 8000


def test_one_email_of_each_kind_per_case(store):
    cid = _case()
    assert store.save_email(cid, 'acknowledgement', 'a@shop.example.test', 's', 'b').startswith('M-')
    assert store.save_email(cid, 'acknowledgement', 'a@shop.example.test', 's2', 'b2') is None
    assert store.save_email(cid, 'decision', 'a@shop.example.test', 's', 'b')
    assert [m['kind'] for m in store.mailbox(cid)] == ['acknowledgement', 'decision']


def test_decision_record_marks_the_queue_entry_decided(store):
    cid = _case()
    store.enqueue(cid, 'CASE-1', 'C-1', 'T-1002', 8000, 'damaged')
    assert store.record_decision(cid, 'D-1', 'approved', 'within limits', 'R11') is True
    assert store.record_decision(cid, 'D-2', 'denied', 'x', 'R10') is False      # first record wins
    assert store.decisions(cid)[0]['decision_id'] == 'D-1'
    assert store.queue(cid)[0]['status'] == 'decided'


def test_outcome_and_kind_are_checked_by_the_database(store):
    with pytest.raises(_write_refused()):
        store.record_decision(_case(), 'D-1', 'approved-by-ceo', 'x', None)
    with pytest.raises(_write_refused()):
        store.save_email(_case(), 'invoice', 'a@shop.example.test', 's', 'b')


@pytest.mark.parametrize('sql', ["UPDATE mailbox SET to_addr = 'x@evil.example' WHERE case_id = ?",
                                 'DELETE FROM mailbox WHERE case_id = ?',
                                 "UPDATE decision_records SET outcome = 'approved' WHERE case_id = ?",
                                 'DELETE FROM decision_records WHERE case_id = ?'])
def test_mailbox_and_decisions_are_append_only(store, sql):
    cid = _case()
    store.save_email(cid, 'acknowledgement', 'a@shop.example.test', 's', 'b')
    store.record_decision(cid, 'D-1', 'denied', 'x', None)
    with pytest.raises(_write_refused()):
        store._write(sql, (cid,))


def test_path_follows_the_control_store(monkeypatch, tmp_path):
    for k in ('TRUSTISSUES_CASEWORK_DB', 'TRUSTISSUES_CONTROL_DB', 'DATABASE_URL'):
        monkeypatch.delenv(k, raising=False)
    assert db_path().endswith(os.path.join('logs', 'casework.db'))
    monkeypatch.setenv('DATABASE_URL', 'postgres://neon.example/db')
    assert db_path() == 'postgres://neon.example/db'
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(tmp_path / 'controls.db'))
    assert db_path() == os.path.join(str(tmp_path), 'casework.db')
    monkeypatch.setenv('TRUSTISSUES_CASEWORK_DB', str(tmp_path / 'other.db'))
    assert db_path() == str(tmp_path / 'other.db')
