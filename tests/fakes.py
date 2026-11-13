"""Test doubles for the integrated service. The real Planner calls the Anthropic API, which tests must not."""


class FixedPlanner:
    """Plans the typical refund case: intake, records, refunds. Records the cases it was asked about."""

    def __init__(self, steps=None):
        self.steps = steps or [
            {'agent': 'intake', 'task': 'Register the case.'},
            {'agent': 'records', 'task': "Look up this customer's own account and transaction."},
            {'agent': 'refunds', 'task': 'Request the refund decision.'},
        ]
        self.calls = []

    def plan(self, case_id, request):
        self.calls.append(case_id)
        return [dict(s) for s in self.steps]
