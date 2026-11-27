"""intake, email and reporting agents.

none of them reads an id, amount or address from the task text. the planner writes that text after reading
the customer's description, so it's treated as noise here. everything comes from the validated form,
the case scope or limit control's decision.

each one checks the kill switch right before it writes, on top of the orchestrator's check before the step.
emails come from fixed templates, never from an LLM, and still go through the output DLP before they're saved.
"""
from decimal import Decimal

from app.casework import get_casework_store
from app.controls import gate
from app.monitoring.audit import log_event
from app.monitoring.detection import get_detector

REASON_LABELS = {'damaged': 'damaged item', 'not_received': 'item not received',
                 'duplicate_charge': 'duplicate charge'}

AI_NOTICE = 'This message was written by an automated AI support agent.'

ACK_SUBJECT = 'We received your refund request ({case_id})'
ACK_BODY = """Hi,

We received your refund request for transaction {transaction_id} (${amount}, {reason}).
Your case reference is {case_id}. We'll email you again when there's a decision.

{notice}

TrustIssues Support
"""

DECISION_SUBJECT = 'Update on your refund request ({case_id})'
DECISION_BODY = """Hi,

{message}

Transaction: {transaction_id}
Case reference: {case_id}

{notice}

TrustIssues Support
"""


def _cents(amount):
    # the form already limits this to 2 decimal places
    return int(Decimal(str(amount)) * 100)


def _halted(agent, case_id):
    log_event(agent, 'kill_switch_check', case_id=case_id, checkpoint='before_write', result='blocked')
    return {'status': 'halted', 'output': 'Stopped: the agent has been stopped by an administrator.'}


def has_decision(case):
    """true once limit control made a decision that actually made it into its audit table."""
    d = case.get('decision')
    return d is not None and d.get('reason') != gate.UNAVAILABLE


def email_due(case):
    """which email this case needs next, or None. acknowledgement first, then the decision once there is one."""
    sent = case.get('emails_sent', ())
    if 'acknowledgement' not in sent:
        return 'acknowledgement'
    if has_decision(case) and 'decision' not in sent:
        return 'decision'
    return None


# ---------------------------------------------------------------- intake
def intake_agent(case_id, task, case):
    scope = case.get('scope')
    if scope is None:
        return {'status': 'error', 'output': 'No case scope, so the case was not queued.'}
    if case.get('queued'):
        return {'status': 'ok', 'output': f'Case {case_id} is already queued.'}
    if gate.is_revoked():
        return _halted('intake-agent', case_id)
    req = case['request']
    added = get_casework_store().enqueue(case_id, scope.case_id, scope.customer_id, scope.transaction_id,
                                         _cents(req['amount']), req['reason'])
    case['queued'] = True
    log_event('intake-agent', 'case_queued', case_id=case_id, scope_case_id=scope.case_id, new=added)
    return {'status': 'ok', 'output': f'Case {case_id} registered and queued.'}


# ---------------------------------------------------------------- email
def render_email(kind, case_id, case):
    req = case['request']
    if kind == 'acknowledgement':
        return (ACK_SUBJECT.format(case_id=case_id),
                ACK_BODY.format(transaction_id=case['scope'].transaction_id, amount='%.2f' % (_cents(req['amount']) / 100),
                                reason=REASON_LABELS.get(req['reason'], 'other'), case_id=case_id, notice=AI_NOTICE))
    # same text the customer sees on the page, so the email can't say more than the page does
    message = gate.public_view(case['decision'])['message']
    return (DECISION_SUBJECT.format(case_id=case_id),
            DECISION_BODY.format(message=message, transaction_id=case['scope'].transaction_id, case_id=case_id,
                                 notice=AI_NOTICE))


def email_agent(case_id, task, case):
    """writes the next email that's due to the mock mailbox. never sends anything for real."""
    scope = case.get('scope')
    if scope is None:
        return {'status': 'error', 'output': 'No case scope, so no email was written.'}
    kind = email_due(case)
    if kind is None:
        return {'status': 'ok', 'output': 'No email is due right now.'}

    # the only address we trust is the one on file, and access control hands it out only while the case is live
    to_addr = gate.records_for(scope, actor='email-agent').recipient()
    if not to_addr:
        log_event('email-agent', 'email_blocked', severity='medium', case_id=case_id, kind=kind, reason='no recipient')
        return {'status': 'denied', 'output': 'No address on file could be used for this case.'}

    subject, body = render_email(kind, case_id, case)
    scan = get_detector().scan_output(subject + '\n' + body, case_id=case_id, customer_id=scope.customer_id,
                                      allowed_emails=[to_addr], extra={'email_kind': kind})
    if not scan.clean:
        # detector already logged the dlp_violation with the details, this just ties it to the email
        log_event('email-agent', 'email_blocked', severity='high', case_id=case_id, kind=kind, reason='dlp',
                  rule_ids=scan.rule_ids)
        return {'status': 'blocked', 'output': 'The email was blocked by the outbound data check.'}

    if gate.is_revoked():
        return _halted('email-agent', case_id)
    message_id = get_casework_store().save_email(case_id, kind, to_addr, subject, body)
    case.setdefault('emails_sent', []).append(kind)
    log_event('email-agent', 'email_saved', case_id=case_id, kind=kind, message_id=message_id,
              to=to_addr, duplicate=message_id is None)
    return {'status': 'ok', 'output': f'{kind.capitalize()} email written to the mailbox (not sent).'}


# ---------------------------------------------------------------- reporting
def reporting_agent(case_id, task, case):
    """records limit control's outcome and reason. the reason stays internal, customers never see it."""
    decision = case.get('decision')
    if decision is None:
        return {'status': 'ok', 'output': 'No decision yet, nothing to report.'}
    if not has_decision(case):
        return {'status': 'error', 'output': 'The decision was not recorded, so there is nothing to report.'}
    if case.get('reported'):
        return {'status': 'ok', 'output': 'The outcome was already recorded.'}
    if gate.is_revoked():
        return _halted('reporting-agent', case_id)
    added = get_casework_store().record_decision(case_id, decision.get('decision_id'), decision['outcome'],
                                                 decision.get('reason') or '', decision.get('rule'))
    case['reported'] = True
    log_event('reporting-agent', 'decision_recorded', case_id=case_id, decision_id=decision.get('decision_id'),
              outcome=decision['outcome'], new=added)
    return {'status': 'ok', 'output': f"Outcome recorded: {decision['outcome']}."}
