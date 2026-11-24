"""The control store on Postgres (the Vercel deployment) behaves like the SQLite one the controls were built on.

Skipped unless TRUSTISSUES_TEST_PG_URL points at a throwaway Postgres database. Every test drops and
recreates the public schema first, so never point this at a database you care about.

  TRUSTISSUES_TEST_PG_URL=postgresql://user:pass@host/db python -m pytest tests/test_pg_store.py

What is covered
  * Blake's retest checks, run unchanged against Postgres (except the ones that open the SQLite file itself)
  * what only a shared hosted database changes: two instances on one ledger, one kill switch, a dropped
    connection, a cap enforced by the schema, an audit table that refuses edits
"""
import os
import threading

import pytest

URL = os.environ.get('TRUSTISSUES_TEST_PG_URL')
pytestmark = pytest.mark.skipif(not URL, reason='set TRUSTISSUES_TEST_PG_URL to run the Postgres tests')

psycopg = pytest.importorskip('psycopg')

# These open the SQLite file directly (raw connections, file locks, dropped triggers), so they say nothing
# about Postgres. Their guarantees are tested below against Postgres itself.
SQLITE_FILE_CHECKS = {'BT-AUD01', 'BT-FAIL02', 'BT-BANK01'}


def reset_schema():
    with psycopg.connect(URL, autocommit=True) as c:
        c.execute('DROP SCHEMA public CASCADE')
        c.execute('CREATE SCHEMA public')


@pytest.fixture
def fresh():
    reset_schema()
    yield URL


def make(url=URL, **kw):
    from app.controls.access_control import AccessControl
    from app.controls.limit_control import LimitControl
    from app.controls.store import Store
    st = Store(url)
    lc = LimitControl(st, require_reason=False, **kw)
    return st, lc, AccessControl(st, lc)


def admin():
    from blueteam.run_retest import admin_principal
    return admin_principal()


def test_blake_retest_checks_hold_on_postgres(monkeypatch):
    import app.controls.authority as authority
    import app.controls.store as store_mod
    from blueteam import run_retest

    real, seen = store_mod.Store, set()

    def on_postgres(path=':memory:', **kw):
        kw.pop('busy_timeout', None)
        if path == ':memory:' or path not in seen:      # a named path is one store, across simulated restarts
            reset_schema()
            seen.add(path)
        return real(URL, **kw)

    monkeypatch.setattr(store_mod, 'Store', on_postgres)
    monkeypatch.setattr(authority, 'Store', on_postgres)
    failed = []
    for c in run_retest.CHECKS:
        if c['id'] in SQLITE_FILE_CHECKS:
            continue
        held, detail = c['fn'](run_retest.Target())
        if not held:
            failed.append('%s: %s' % (c['id'], str(detail)[:300]))
    assert not failed, '\n'.join(failed)


def test_two_instances_share_one_ledger_and_cap(fresh):
    """Two serverless instances are two stores on one database. The cap is the database's, not a process's."""
    _, lc1, _ = make()
    _, lc2, _ = make()
    outcomes = []
    for n in range(1004, 1009):                        # five $100 refunds, alternating instances: $500
        outcomes.append((lc1 if n % 2 else lc2).decide('C-1', f'T-{n}', '100.00')['outcome'])
    assert outcomes == ['approved'] * 5
    assert lc1.decide('C-1', 'T-1009', '1.00')['outcome'] == 'denied'
    assert lc2.decide('C-1', 'T-1009', '1.00')['outcome'] == 'denied'
    assert lc2.decide('C-1', 'T-1004', '1.00')['reason'] == 'transaction already refunded'


def test_kill_switch_is_shared_and_restorable_from_another_instance(fresh):
    """Engage on instance A, restore on instance B: A must follow the database, not its own memory."""
    st1, lc1, _ = make()
    _, lc2, _ = make()
    lc1.engage_kill_switch(actor='detector', reason='incident')
    assert lc1.is_revoked() and lc2.is_revoked()
    assert lc2.decide('C-1', 'T-1004', '10.00')['outcome'] == 'denied'
    assert lc2.restore_authority(admin(), 'resolved')['outcome'] == 'ok'
    assert not lc1.is_revoked()
    assert lc1.decide('C-1', 'T-1004', '10.00')['outcome'] == 'approved'
    assert st1.verify_audit_chain()


def test_parallel_instances_cannot_overspend_the_cap(fresh):
    """Ten instances race to spend $100 each on ten transactions: exactly five may be approved."""
    from app.controls.store import Store
    seed = Store(URL)
    seed.conn.executemany('INSERT INTO transactions VALUES (?,?,?)', [(f'T-{n}', 'C-1', 10000) for n in range(2001, 2011)])
    results, barrier = [], threading.Barrier(10)

    def worker(n):
        _, lc, _ = make()
        barrier.wait()
        results.append(lc.decide('C-1', f'T-{n}', '100.00')['outcome'])

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(2001, 2011)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results).count('approved') == 5, results
    assert seed.one("SELECT COALESCE(SUM(amount_cents),0) FROM refunds WHERE status != 'void'")[0] == 50000
    assert seed.verify_audit_chain()


def test_the_schema_itself_refuses_what_the_code_refuses(fresh):
    """Even a writer that skips LimitControl cannot break the rules: they are constraints and triggers."""
    st, _, _ = make()
    row = "INSERT INTO refunds VALUES (?, ?, 'C-1', ?, ?, 'settled', 'agent')"
    st.conn.execute(row, ('D-1', 'T-1004', 10000, 1))
    with pytest.raises(psycopg.IntegrityError):                  # second refund on a transaction
        st.conn.execute(row, ('D-2', 'T-1004', 10000, 2))
    with pytest.raises(psycopg.IntegrityError):                  # agent refund over $100
        st.conn.execute(row, ('D-3', 'T-1001', 10001, 3))
    for i, n in enumerate(range(1005, 1009)):                    # $400 more: $500 in the window
        st.conn.execute(row, (f'D-{10 + i}', f'T-{n}', 10000, 10 + i))
    with pytest.raises(psycopg.DatabaseError, match='weekly cap'):
        st.conn.execute(row, ('D-99', 'T-1009', 100, 20))


def test_audit_table_is_append_only_and_tampering_is_detected(fresh):
    st, lc, _ = make()
    lc.decide('C-1', 'T-1004', '10.00')
    lc.decide('C-1', 'T-1005', '20.00')
    assert st.verify_audit_chain()
    with pytest.raises(psycopg.DatabaseError, match='append-only'):
        st.conn.execute("UPDATE audit SET body = '{}' WHERE seq = (SELECT MIN(seq) FROM audit)")
    with pytest.raises(psycopg.DatabaseError, match='append-only'):
        st.conn.execute('DELETE FROM audit')
    assert st.verify_audit_chain()
    # someone with owner rights drops the triggers and edits a row: the chain no longer verifies
    st.conn.execute('DROP TRIGGER audit_no_update ON audit')
    st.conn.execute("UPDATE audit SET body = replace(body, 'approved', 'denied') WHERE seq = (SELECT MIN(seq) FROM audit)")
    assert not st.verify_audit_chain()


def test_revocation_landing_between_reserve_and_bank_voids_the_reservation(fresh):
    """The Postgres version of the last case in BT-BANK01: a revoke from another connection mid-decision."""
    late = []
    st, lc, _ = make(bank=lambda **kw: late.append(kw))
    other = psycopg.connect(URL, autocommit=True)
    commit = st.commit

    def commit_then_revoke():
        commit()
        other.execute('UPDATE authority_state SET revoked = 1')
    st.commit = commit_then_revoke
    res = lc.decide('C-1', 'T-1004', '10.00')
    other.close()
    assert (res['outcome'], res['reason'], len(late)) == ('denied', 'authority revoked', 0)
    assert st.all('SELECT status FROM refunds') == [('void',)]


def test_a_dropped_connection_is_replaced_not_fatal(fresh):
    """A hosted database closes idle connections. The next request must reconnect, not fail closed forever."""
    st, lc, _ = make()
    assert lc.decide('C-1', 'T-1004', '10.00')['outcome'] == 'approved'
    with psycopg.connect(URL, autocommit=True) as killer:
        killer.execute('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() '
                       "AND datname = current_database() AND application_name = ''")
    # the very next calls work: the read and the transaction both reconnect once, nothing fails closed
    assert not lc.is_revoked()
    assert lc.decide('C-1', 'T-1005', '10.00')['outcome'] == 'approved'


def test_records_source_reads_the_same_database(fresh, monkeypatch):
    from app.controls import gate
    from app.rag.records_source import ControlDBSource, pick_source
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', URL)
    monkeypatch.delenv('TRUSTISSUES_RECORDS_SOURCE', raising=False)
    gate._reset_for_tests()
    try:
        src = pick_source(None)
        assert isinstance(src, ControlDBSource)
        assert src.get_transaction('T-1003')['customer_id'] == 'C-2'
        assert src.get_customer('C-1')['account_last4'] == '4401'
        assert 'account_no' not in src.get_customer('C-1')
    finally:
        gate._reset_for_tests()
