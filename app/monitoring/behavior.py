"""Behaviour-based detection: alerts from patterns across many audit events.

Single inputs can look harmless while the sequence is an attack: splitting a big refund into
many small ones (RT-03), probing other customers' records one id at a time (RT-28), retrying an
injection with different obfuscation (RT-22), or the agent doing something after its authority
was revoked (RT-05, RT-12). These rules read the audit log and raise alerts.

It understands three event shapes so it works across the team's code:
  this module's log    {'action': ..., 'actor': ..., 'customer_id': ..., 'timestamp': ISO}
  Sargis's orchestrator {'action': 'kill_switch_revoke' | 'step_start' | ...}
  Blake's control store {'kind': 'refund_decision' | 'records_access' | 'kill_switch', 'outcome': ...,
                         'at_us': microseconds}

run() returns alerts and logs each new one as action 'security_alert'. It does not act on its
own. A caller (an admin endpoint, a cron, or the orchestrator) decides whether an alert should
engage the kill switch. That keeps a flood of fake alerts from becoming a denial of service.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.monitoring.audit import get_audit_log, SEVERITY_RANK

# actions that count as the agent doing something consequential
CONSEQUENTIAL = {'refund_issued', 'refund_decision', 'settlement', 'email_sent', 'tool_call', 'step_start',
                 'bank_account_access', 'records_access'}
REVOKE = {'kill_switch_revoke', 'kill_switch_engaged', 'authority_revoked'}
RESTORE = {'kill_switch_restore', 'kill_switch_released', 'authority_restored'}


def _ts(e):
    if 'at_us' in e and isinstance(e['at_us'], (int, float)):
        return datetime.fromtimestamp(e['at_us'] / 1e6, tz=timezone.utc)
    try:
        t = datetime.fromisoformat(str(e.get('timestamp') or e.get('at')))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _action(e):
    a = e.get('action') or e.get('kind') or ''
    if a == 'kill_switch':                                     # Blake's single kind with engaged/outcome fields
        engaged = e.get('engaged', e.get('outcome') in ('engaged', 'revoked'))
        return 'kill_switch_engaged' if engaged else 'kill_switch_released'
    return a


def _who(e):
    return e.get('customer_id') or (e.get('raw') or {}).get('customer_id') or e.get('actor') or 'unknown'


def _denied(e):
    return e.get('outcome') in ('denied', 'escalated') or e.get('allowed') is False or e.get('result') == 'blocked'


class BehaviorMonitor:
    def __init__(self, audit=None, *, injection_threshold=3, injection_window=timedelta(minutes=30),
                 records_threshold=3, records_window=timedelta(minutes=10),
                 refund_threshold=4, refund_window=timedelta(hours=1),
                 rate_threshold=20, rate_window=timedelta(minutes=5)):
        self._audit = audit
        self.cfg = dict(injection=(injection_threshold, injection_window), records=(records_threshold, records_window),
                        refunds=(refund_threshold, refund_window), rate=(rate_threshold, rate_window))

    @property
    def audit(self):
        return self._audit or get_audit_log()

    @staticmethod
    def _bursts(events, threshold, window):
        """Groups of >= threshold events inside `window` (events sorted by time)."""
        out, start = [], 0
        for end in range(len(events)):
            while events[end][0] - events[start][0] > window:
                start += 1
            if end - start + 1 >= threshold:
                out.append(events[start:end + 1])
        return out[-1:] if out else []      # one alert per subject: the latest, largest burst

    def analyze(self, events):
        """Pure function over a list of events. Returns a list of alert dicts."""
        alerts = []
        timed = sorted(((t, e) for e in events if (t := _ts(e)) is not None), key=lambda x: x[0])

        # 1. repeated attack attempts from the same customer
        n, w = self.cfg['injection']
        by = defaultdict(list)
        for t, e in timed:
            if _action(e) == 'attack_detected' and e.get('verdict') in ('suspicious', 'malicious'):
                by[_who(e)].append((t, e))
        for who, evs in by.items():
            for burst in self._bursts(evs, n, w):
                rules = sorted({r for _, e in burst for r in e.get('rule_ids', [])})
                alerts.append(self._alert('BEH-REPEATED-ATTACK', 'high', who, burst,
                                          '%d attack detections from %s within %s' % (len(burst), who, w),
                                          ['LLM01', 'ASI01'], rules=rules))

        # 2. records enumeration: many denied record lookups
        n, w = self.cfg['records']
        by = defaultdict(list)
        for t, e in timed:
            a = _action(e)
            if a in ('records_access', 'records_access_denied', 'case_store_denied', 'case_update_denied') and \
                    (a.endswith('denied') or _denied(e)):
                by[_who(e)].append((t, e))
            elif a == 'attack_detected' and {'CROSS-CUSTOMER', 'BULK-ENUM', 'LOOKUP-BY-EMAIL'} & set(e.get('rule_ids', [])):
                by[_who(e)].append((t, e))
        for who, evs in by.items():
            for burst in self._bursts(evs, n, w):
                alerts.append(self._alert('BEH-RECORDS-ENUMERATION', 'high', who, burst,
                                          '%d denied or cross-customer record requests from %s within %s'
                                          % (len(burst), who, w), ['LLM02', 'ASI03']))

        # 3. refund limit probing / splitting
        n, w = self.cfg['refunds']
        by = defaultdict(list)
        for t, e in timed:
            if _action(e) in ('refund_decision', 'refund_requested', 'refund_issued'):
                by[_who(e)].append((t, e))
        for who, evs in by.items():
            for burst in self._bursts(evs, n, w):
                denied = sum(1 for _, e in burst if _denied(e))
                alerts.append(self._alert('BEH-REFUND-PROBING', 'high' if denied >= 2 else 'medium', who, burst,
                                          '%d refund requests from %s within %s (%d denied or escalated): possible '
                                          'split refunds or limit probing' % (len(burst), who, w, denied),
                                          ['LLM03', 'ASI02']))

        # 4. consequential action after revocation
        revoked_at = None
        for t, e in timed:
            a = _action(e)
            if a in REVOKE:
                revoked_at = revoked_at or t
            elif a in RESTORE or (a == 'service_started' and not e.get('authority_revoked')):
                revoked_at = None      # the starter kill switch is in memory, so a restart clears it
            elif revoked_at and a in CONSEQUENTIAL and not _denied(e):
                alerts.append(self._alert('BEH-ACTION-AFTER-REVOKE', 'critical', e.get('actor', 'unknown'), [(t, e)],
                                          '%s by %s after authority was revoked at %s' % (a, e.get('actor'),
                                                                                          revoked_at.isoformat()),
                                          ['ASI10', 'LLM03']))

        # 5. request flood from one customer (unbounded consumption)
        n, w = self.cfg['rate']
        by = defaultdict(list)
        for t, e in timed:
            if _action(e) in ('case_received', 'refund_requested', 'task_submitted', 'case_stored'):
                by[_who(e)].append((t, e))
        for who, evs in by.items():
            for burst in self._bursts(evs, n, w):
                alerts.append(self._alert('BEH-REQUEST-FLOOD', 'medium', who, burst,
                                          '%d requests from %s within %s' % (len(burst), who, w), ['LLM06']))
        return alerts

    @staticmethod
    def _alert(rule_id, severity, subject, burst, summary, owasp, **extra):
        ids = [e.get('event_id') or e.get('decision_id') or e.get('seq') for _, e in burst]
        return {'rule_id': rule_id, 'severity': severity, 'subject': subject, 'summary': summary, 'owasp': owasp,
                'first_seen': burst[0][0].isoformat(), 'last_seen': burst[-1][0].isoformat(),
                'evidence_event_ids': [i for i in ids if i is not None][:50], **extra}

    def run(self, extra_events=(), *, log=True):
        """Analyse the audit log (plus any extra events, e.g. Blake's control audit rows), log new alerts,
        and also check the audit chain itself."""
        events = self.audit.read() + list(extra_events)
        alerts = self.analyze([e for e in events if e.get('action') != 'security_alert'])
        chain = self.audit.verify()
        if not chain['ok']:
            alerts.append({'rule_id': 'BEH-AUDIT-TAMPER', 'severity': 'critical', 'subject': 'audit log',
                           'summary': 'Audit log hash chain is broken: %s at line %s' % (chain['problem'], chain['line']),
                           'owasp': ['MAESTRO-L5'], 'evidence_event_ids': []})
        if log:
            seen = {(a.get('rule_id'), a.get('subject'), a.get('last_seen'))
                    for a in self.audit.read(action='security_alert')}
            for a in alerts:
                if (a['rule_id'], a['subject'], a.get('last_seen')) not in seen:
                    self.audit.log('behavior_monitor', 'security_alert', **a)
        return sorted(alerts, key=lambda a: -SEVERITY_RANK[a['severity']])
