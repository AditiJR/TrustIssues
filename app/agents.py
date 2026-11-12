"""the five specialized agents. all stubs for now, nothing here has side effects yet.

each one only gets its own case, the orchestrator never hands over other customers' records.
Blake's access control and limit control still need to go in front of records and refunds.
"""


def intake_agent(case_id: str, task: str, case: dict) -> dict:
    return {'status': 'ok', 'output': f'[STUB] Case {case_id} registered and queued.'}


def email_agent(case_id: str, task: str, case: dict) -> dict:
    return {'status': 'ok', 'output': '[STUB] Email drafted, not sent.'}


def records_agent(case_id: str, task: str, case: dict) -> dict:
    return {
        'status': 'ok',
        'output': (f"[STUB] Would look up customer {case['request']['customer_id']} / "
                   f"transaction {case['request']['transaction_id']}. No records read."),
    }


def refunds_agent(case_id: str, task: str, case: dict) -> dict:
    # never moves money. a real decision has to go through limit control first
    return {'status': 'ok', 'output': '[STUB] Decision pending. No limit check yet, no money moved.'}


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
