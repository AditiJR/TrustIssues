"""the core orchestrator: plan, validate, route, aggregate.

only the orchestrator calls agents, and only through AGENT_REGISTRY (the allowlist).
the LLM planner just proposes steps, this file decides what actually runs.
"""

from datetime import datetime, timezone
import json
import os
import threading
import uuid

from app.agent import Planner, PlannerError
from app.agents import AGENT_REGISTRY
from app.killswitch import KillSwitch

MAX_STEPS = 8
MAX_TASK_CHARS = 300

LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'events.jsonl')
_log_lock = threading.Lock()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def log_event(action: str, **fields):
    entry = {'timestamp': _now_iso(), 'actor': 'orchestrator', 'action': action, **fields}
    # TODO(Vaishnavi): I'm writing to your log file in the same format. Want to make a shared log_event() so we both use the same thingys?
    with _log_lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(entry) + '\n')


class Orchestrator:
    def __init__(self, planner: Planner, kill_switch: KillSwitch):
        self.planner = planner
        self.kill_switch = kill_switch
        # short-term memory: case_id -> {request, plan, results, status}. gone on restart
        self.memory = {}

    def revoke_authority(self, reason: str) -> dict:
        changed = self.kill_switch.revoke(reason)
        log_event('kill_switch_revoke', reason=reason, changed=changed)
        return self.kill_switch.status()

    def _authority_ok(self, case_id: str, checkpoint: str) -> bool:
        # logs every check, even the allowed ones, so the audit log shows we actually checked
        revoked = self.kill_switch.is_revoked()
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
        case = {'request': request, 'plan': None, 'results': [], 'status': 'received'}
        self.memory[case_id] = case
        log_event('case_received', case_id=case_id, request=request)

        # kill switch goes first so a revoked agent doesn't even call the model
        if not self._authority_ok(case_id, 'before_plan'):
            return self._finish(case_id, 'halted', 'The agent has been stopped by an administrator.')
        try:
            proposed = self.planner.plan(case_id, request)
        except PlannerError as e:
            log_event('plan_failed', case_id=case_id, error=str(e))
            return self._finish(case_id, 'planner_failed', 'We could not process your request right now.')
        log_event('plan_proposed', case_id=case_id, steps=proposed)

        # the model's agent list is just a suggestion, this is the real check
        steps, reason = self._validate_plan(proposed)
        if steps is None:
            log_event('plan_rejected', case_id=case_id, reason=reason)
            return self._finish(case_id, 'plan_rejected', 'We could not process your request right now.')
        case['plan'] = steps
        log_event('plan_accepted', case_id=case_id, step_count=len(steps))

        # check again before every step so a revoke mid-case stops the rest
        for i, step in enumerate(steps, 1):
            if not self._authority_ok(case_id, f'before_step_{i}'):
                return self._finish(case_id, 'halted', 'The agent has been stopped by an administrator.')
            log_event('step_start', case_id=case_id, step=i, agent=step['agent'], task=step['task'])
            # TODO(Blake): your limit control goes here, before the refund runs. Anything over $100 or the weekly $500 should get stopped or sent to admin, assuming i actully set it up right.
            # TODO(Blake): access control, goes here so records only returns stuff for the current case.
            agent_fn = AGENT_REGISTRY[step['agent']]
            try:
                result = agent_fn(case_id, step['task'], case)
            except Exception as e:  # one broken agent shouldn't take down the whole request
                result = {'status': 'error', 'output': f'{type(e).__name__}'}
            case['results'].append({'step': i, **step, 'result': result})
            log_event('step_done', case_id=case_id, step=i, agent=step['agent'], result=result)

        # plain code for now. the final message is fixed text, the model doesn't write it
        failed = [r for r in case['results'] if r['result'].get('status') != 'ok']
        if failed:
            return self._finish(case_id, 'error', 'Part of your request could not be processed.')
        return self._finish(case_id, 'completed',
                            'Your request was received and is pending review. '
                            '(Prototype: no refund decision is made yet.)')

    def _finish(self, case_id: str, status: str, message: str) -> dict:
        case = self.memory[case_id]
        case['status'] = status
        log_event('case_finished', case_id=case_id, status=status)
        return {
            'case_id': case_id,
            'status': status,
            'message': message,
            'steps': case['results'],
        }
