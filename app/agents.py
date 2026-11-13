"""the five specialized agents. intake, email and reporting are still stubs.

records is Vaishnavi's agent (app/records_agent.py), reading through Blake's case-scoped gateway.
refunds asks Blake's limit control for the decision. it never moves money or sets a limit itself.
each one only gets its own case, the orchestrator never hands over other customers' records.
"""

from app.controls import gate
from app.records_agent import records_agent


def intake_agent(case_id: str, task: str, case: dict) -> dict:
    return {'status': 'ok', 'output': f'[STUB] Case {case_id} registered and queued.'}


def email_agent(case_id: str, task: str, case: dict) -> dict:
    return {'status': 'ok', 'output': '[STUB] Email drafted, not sent.'}


def refunds_agent(case_id: str, task: str, case: dict) -> dict:
    """asks limit control for the decision. the amount, reason and the customer/transaction pair come from
    the validated form and the case scope, never from the planner's task text."""
    scope = case.get('scope')
    if scope is None:
        return {'status': 'error', 'output': 'No case scope, so no decision was requested.'}
    if case.get('decision') is not None:      # a plan that lists refunds twice must not request twice
        return {'status': 'ok', 'output': 'A decision was already recorded for this case.'}
    req = case['request']
    decision = gate.request_refund(scope, req['amount'], req['reason'], req.get('description'))
    case['decision'] = decision
    if decision.get('reason') == gate.UNAVAILABLE:
        return {'status': 'error', 'output': 'The decision could not be recorded.'}
    return {'status': 'ok', 'output': f"Decision: {decision['outcome']} (reference {decision['decision_id']})."}


def reporting_agent(case_id: str, task: str, case: dict) -> dict:
    return {'status': 'ok', 'output': '[STUB] Report entry recorded (placeholder).'}


# the allowlist. if an agent isn't in here, the orchestrator won't run it
AGENT_REGISTRY = {
    'intake': intake_agent,
    'email': email_agent,
    'records': records_agent,
    'refunds': refunds_agent,
    'reporting': reporting_agent,
}
