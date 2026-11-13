import json
import threading

from app.monitoring.audit import AuditLog, redact, log_event, get_audit_log


def lines(log):
    with open(log.path) as fh:
        return [json.loads(x) for x in fh if x.strip()]


def test_chain_verifies_and_keeps_starter_fields(audit):
    for i in range(5):
        audit.log('agent', 'step', case_id='CASE-1', step=i)
    rep = audit.verify()
    assert rep['ok'] and rep['chained'] == 5
    e = lines(audit)[0]
    assert {'timestamp', 'actor', 'action', 'seq', 'event_id', 'severity', 'prev_hash', 'hash'} <= set(e)


def test_edit_delete_and_reorder_are_detected(audit):
    for i in range(4):
        audit.log('agent', 'step', n=i)
    raw = open(audit.path).read().splitlines()

    edited = list(raw)
    e = json.loads(edited[1]); e['n'] = 99; edited[1] = json.dumps(e)
    open(audit.path, 'w').write('\n'.join(edited) + '\n')
    assert audit.verify()['problem'] == 'content changed after it was written'

    open(audit.path, 'w').write('\n'.join(raw[:1] + raw[2:]) + '\n')
    assert not audit.verify()['ok']

    open(audit.path, 'w').write('\n'.join([raw[1], raw[0]] + raw[2:]) + '\n')
    assert not audit.verify()['ok']


def test_legacy_starter_lines_allowed_only_before_chain(audit):
    legacy = json.dumps({'timestamp': 't', 'actor': 'agent', 'action': 'plan_and_simulate'})
    open(audit.path, 'w').write(legacy + '\n')
    audit.log('agent', 'step')
    assert audit.verify()['ok'] and audit.verify()['legacy_unchained'] == 1
    with open(audit.path, 'a') as fh:          # an attacker appending a raw, unchained line
        fh.write(json.dumps({'timestamp': 't', 'actor': 'admin', 'action': 'kill_switch', 'engaged': False}) + '\n')
    assert audit.verify()['problem'] == 'unchained line after chain start'


def test_newline_json_cannot_forge_entry(audit, payloads):
    audit.log('agent', 'plan_and_simulate', task=payloads['form_free_text']['log_forge'])
    entries = lines(audit)
    assert len(entries) == 1 and entries[0]['actor'] == 'agent'


def test_redaction_masks_accounts_emails_and_secrets(audit):
    e = audit.log('agent', 'x', note='acct 000111222333 card 4111 1111 1111 1111 mail c1.customer@shop.example.test',
                  api_key='sk-live-abc', nested={'account_no': '000444555666'}, amount_cents=25000, txn='T-1001')
    blob = open(audit.path).read()
    assert '000111222333' not in blob and '4111 1111' not in blob and 'c1.customer@' not in blob
    assert '***2333' in blob and 'shop.example.test' in blob          # last4 and domain kept for investigators
    assert e['api_key'] == '<REDACTED>' and e['nested']['account_no'] == '<REDACTED>'
    assert e['amount_cents'] == 25000 and e['txn'] == 'T-1001'


def test_reserved_fields_cannot_be_overridden(audit):
    e = audit.log('agent', 'x', hash='0' * 64, seq=1, actor_detail='ok')
    assert e['seq'] == 1 and e['hash'] != '0' * 64 and audit.verify()['ok']


def test_concurrent_writers_keep_chain_valid(audit):
    other = AuditLog(audit.path)             # second instance, as if from another module

    def work(log, n):
        for i in range(n):
            log.log('t', 'x', i=i)
    ts = [threading.Thread(target=work, args=(audit if k % 2 else other, 25)) for k in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    rep = audit.verify()
    assert rep['ok'] and rep['chained'] == 100


def test_read_filters(audit):
    audit.log('a', 'one', case_id='C1')
    audit.log('a', 'two', case_id='C2', severity='high')
    assert [e['action'] for e in audit.read(case_id='C2')] == ['two']
    assert [e['action'] for e in audit.read(min_severity='medium')] == ['two']
    assert len(audit.read(action={'one', 'two'})) == 2


def test_module_shortcut_follows_env(isolated_paths):
    log_event('svc', 'hello')
    assert get_audit_log().read()[0]['action'] == 'hello'


def test_redact_handles_odd_types():
    assert redact({'a': (1, 2), 'b': None, 'c': object.__name__})['a'] == [1, 2]
