from datetime import datetime, timedelta, timezone

from app.monitoring.behavior import BehaviorMonitor

T0 = datetime(2026, 11, 12, 18, 0, tzinfo=timezone.utc)


def ev(minutes, action, **kw):
    return {'timestamp': (T0 + timedelta(minutes=minutes)).isoformat(), 'action': action, 'event_id': 'E%s' % minutes,
            **kw}


def rules(alerts):
    return {a['rule_id'] for a in alerts}


def test_repeated_attacks_from_one_customer():
    events = [ev(i, 'attack_detected', verdict='malicious', customer_id='C-1', rule_ids=['INJ-OVERRIDE'])
              for i in (0, 3, 9)]
    a = BehaviorMonitor().analyze(events)
    assert 'BEH-REPEATED-ATTACK' in rules(a) and a[0]['subject'] == 'C-1'
    spread = [ev(i, 'attack_detected', verdict='malicious', customer_id='C-1') for i in (0, 40, 80)]
    assert 'BEH-REPEATED-ATTACK' not in rules(BehaviorMonitor().analyze(spread))


def test_records_enumeration_with_blake_shaped_events():
    blake = [{'kind': 'records_access', 'outcome': 'denied', 'actor': 'records-agent', 'customer_id': 'C-1',
              'at_us': int((T0 + timedelta(minutes=i)).timestamp() * 1e6), 'decision_id': 'R-%d' % i} for i in range(3)]
    assert 'BEH-RECORDS-ENUMERATION' in rules(BehaviorMonitor().analyze(blake))


def test_refund_probing():
    events = [ev(i * 5, 'refund_decision', customer_id='C-1', outcome='denied' if i > 1 else 'approved')
              for i in range(5)]
    a = [x for x in BehaviorMonitor().analyze(events) if x['rule_id'] == 'BEH-REFUND-PROBING']
    assert a and a[0]['severity'] == 'high'


def test_action_after_revoke_is_critical_and_restore_clears():
    events = [ev(0, 'kill_switch_revoke', actor='orchestrator'),
              ev(1, 'step_start', actor='orchestrator', case_id='X'),
              ev(2, 'kill_switch_check', result='blocked')]
    a = BehaviorMonitor().analyze(events)
    assert [x['severity'] for x in a if x['rule_id'] == 'BEH-ACTION-AFTER-REVOKE'] == ['critical']
    events = [ev(0, 'kill_switch_revoke'), ev(1, 'service_started'), ev(2, 'step_start')]
    assert 'BEH-ACTION-AFTER-REVOKE' not in rules(BehaviorMonitor().analyze(events))
    denied = [ev(0, 'kill_switch_revoke'), ev(1, 'refund_decision', outcome='denied')]
    assert 'BEH-ACTION-AFTER-REVOKE' not in rules(BehaviorMonitor().analyze(denied))


def test_request_flood():
    events = [ev(i * 0.1, 'case_received', customer_id='C-3') for i in range(25)]
    assert 'BEH-REQUEST-FLOOD' in rules(BehaviorMonitor().analyze(events))


def test_run_logs_alerts_once_and_flags_tampering(audit):
    for i in range(3):
        audit.log('detector', 'attack_detected', verdict='malicious', customer_id='C-1', rule_ids=['X'])
    m = BehaviorMonitor(audit)
    assert 'BEH-REPEATED-ATTACK' in rules(m.run())
    m.run()
    assert len(audit.read(action='security_alert')) == 1
    raw = open(audit.path).read().replace('"C-1"', '"C-9"', 1)
    open(audit.path, 'w').write(raw)
    assert 'BEH-AUDIT-TAMPER' in rules(m.run(log=False))
