"""the core orchestrator: plan, validate, route, aggregate.

only the orchestrator calls agents, and only through AGENT_REGISTRY (the allowlist).
the LLM planner just proposes steps, this file decides what actually runs.

integration notes:
  * the kill switch is Blake's (app.controls.gate), stored in the control DB. it is checked before
    planning and before every step, so a revoke stops the planner and the remaining steps, not just refunds.
  * the ownership check goes through the gate (open_case) before anything is planned. the resulting
    scope is handed to the records agent (as a RecordsGateway) and to the refunds agent. agents never
    receive a customer or transaction id they could point somewhere else.
  * the final refund decision comes from Blake's limit control, never from the planner or an agent's text.
  * events go to the shared hash-chained audit log (Vaishnavi's app.monitoring.audit).
"""

import uuid

from app.agent import Planner, PlannerError
from app.agents import AGENT_REGISTRY
from app.controls import gate
from app.monitoring.audit import log_event as _audit_event

MAX_STEPS = 8
MAX_TASK_CHARS = 300

HALTED_MESSAGE = 'The agent has been stopped by an administrator.'
FAILED_MESSAGE = 'We could not process your request right now.'


def log_event(action: str, **fields):
    _audit_event('orchestrator', action, **fields)


class Orchestrator:
    def __init__(self, planner: Planner):
        self.planner = planner
        # short-term memory: case_id -> {request, plan, results, status}. gone on restart
        self.memory = {}

    def revoke_authority(self, reason: str) -> dict:
        """stops the agent. restoring it needs the admin token (POST /admin/kill-switch)."""
        result = gate.engage_kill_switch(actor='orchestrator', reason=reason)
        log_event('kill_switch_revoke', reason=reason)
        return result

    def _authority_ok(self, case_id: str, checkpoint: str) -> bool:
        # logs every check, even the allowed ones, so the audit log shows we actually checked
        revoked = gate.is_revoked()
        log_event('kill_switch_check', case_id=case_id, checkpoint=checkpoint,
                  result='blocked' if revoked else 'allowed')
        return not revoked

    @staticmethod
    def _validate_plan(steps):
        # one bad step kills the whole plan. if the planner made up an agent, the rest of its plan can't be trusted either
        if not steps:
            return None, 'empty plan'
        if len(steps) > MAX_STEPS:
            return None, f'too many steps ({len(steps)} > {MAX_STEPS})'
        clean = []
        for i, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                return None, f'step {i} is not an object'
            agent = step.get('agent')
            task = step.get('task')
            if agent not in AGENT_REGISTRY:
                return None, f'step {i} names unknown agent {agent!r}'
            if not isinstance(task, str) or not task.strip():
                return None, f'step {i} has no task'
            clean.append({'agent': agent, 'task': task.strip()[:MAX_TASK_CHARS]})
        return clean, None

    def handle_refund_request(self, request: dict) -> dict:
        case_id = f'case-{uuid.uuid4().hex[:12]}'
        case = {'request': request, 'plan': None, 'results': [], 'status': 'received',
                'scope': None, 'decision': None}
        self.memory[case_id] = case
        log_event('case_received', case_id=case_id, request=request)

        # kill switch goes first so a revoked agent doesn't even call the model
        if not self._authority_ok(case_id, 'before_plan'):
            return self._finish(case_id, 'halted', HALTED_MESSAGE)

        # ownership check, through the gate. a pair that doesn't match gets an audited denial from limit
        # control (same body as any other denial) and never reaches the planner
        scope, _ = gate.open_case(request['customer_id'], request['transaction_id'])
        if scope is None:
            case['decision'] = gate.handle_refund_form(
                request['customer_id'], request['transaction_id'], request['amount'],
                request['reason'], request.get('description'))
            return self._finish(case_id, 'completed', FAILED_MESSAGE)
        case['scope'] = scope
        case['records_gateway'] = gate.records_for(scope)
        try:
            return self._run_case(case_id, case)
        finally:
            gate.close_case(scope)

    def _run_case(self, case_id: str, case: dict) -> dict:
        try:
            proposed = self.planner.plan(case_id, case['request'])
        except PlannerError as e:
            log_event('plan_failed', case_id=case_id, error=str(e))
            return self._finish(case_id, 'planner_failed', FAILED_MESSAGE)
        log_event('plan_proposed', case_id=case_id, steps=proposed)

        # the model's agent list is just a suggestion, this is the real check
        steps, reason = self._validate_plan(proposed)
        if steps is None:
            log_event('plan_rejected', case_id=case_id, reason=reason)
            return self._finish(case_id, 'plan_rejected', FAILED_MESSAGE)
        case['plan'] = steps
        log_event('plan_accepted', case_id=case_id, step_count=len(steps))

        # check again before every step so a revoke mid-case stops the rest
        for i, step in enumerate(steps, 1):
            if not self._authority_ok(case_id, f'before_step_{i}'):
                return self._finish(case_id, 'halted', HALTED_MESSAGE)
            log_event('step_start', case_id=case_id, step=i, agent=step['agent'], task=step['task'])
            agent_fn = AGENT_REGISTRY[step['agent']]
            try:
                result = agent_fn(case_id, step['task'], case)
            except Exception as e:  # one broken agent shouldn't take down the whole request
                result = {'status': 'error', 'output': f'{type(e).__name__}'}
            case['results'].append({'step': i, **step, 'result': result})
            log_event('step_done', case_id=case_id, step=i, agent=step['agent'], status=result.get('status'))

        failed = [r for r in case['results'] if r['result'].get('status') != 'ok']
        if failed:
            return self._finish(case_id, 'error', 'Part of your request could not be processed.')
        return self._finish(case_id, 'completed', 'Your request was processed.')

    def _finish(self, case_id: str, status: str, message: str) -> dict:
        case = self.memory[case_id]
        decision = case.get('decision')
        body = {'case_id': case_id, 'status': status, 'message': message,
                # customers see the agent and its output, not the raw record each agent read
                'steps': [{'step': r['step'], 'agent': r['agent'], 'task': r['task'],
                           'result': {'status': r['result'].get('status'), 'output': r['result'].get('output')}}
                          for r in case['results']]}
        if decision is not None:
            if decision.get('reason') == gate.UNAVAILABLE:
                # the decision was not written to the audit table, so it is not shown
                status = body['status'] = 'unavailable'
                body['outcome'] = 'denied'                  # never shown: the endpoint answers 503
            else:
                body.update(gate.public_view(decision))     # outcome, message, reference
        elif status == 'completed':
            body['outcome'] = 'pending'                     # the plan never reached the refunds agent
        else:
            body['outcome'] = 'denied'                      # stopped before any decision was made
        if body['outcome'] == 'denied':
            # every denial must look the same from outside. showing steps only when the pair is owned
            # would tell a caller which customer/transaction pairs exist, so a denial shows none
            body['steps'] = []
        case['status'] = status
        log_event('case_finished', case_id=case_id, status=status, outcome=body.get('outcome'),
                  decision_id=decision.get('decision_id') if decision else None)
        return body
