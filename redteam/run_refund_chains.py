#!/usr/bin/env python3
"""Red-team attack chains against refund authority and revocation (RT-02..RT-08).

Runs in-process against app.refund (synthetic data, no network). Each chain
records PASS when the control held. Evidence goes to redteam/results/refund_chains_<ts>.json.

Usage (from repo root): python redteam/run_refund_chains.py
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.refund import RefundAuthority  # noqa: E402


def chain_rt02_amount_boundaries():
    a = RefundAuthority()
    cases = {'100.00': 'approved', '100.01': 'escalated', '-5': 'denied', '0': 'denied',
             'NaN': 'denied', 'Infinity': 'denied', 'abc': 'denied', '1e9': 'denied', '10.001': 'denied'}
    got, ok = {}, True
    for i, (amt, want) in enumerate(cases.items()):
        a = RefundAuthority()
        res = a.request_refund('C-1', 'T-1001', amt)['outcome']
        got[amt] = res
        ok &= res == want
    return ok, got


def chain_rt03_split_to_evade_weekly_cap():
    a = RefundAuthority()
    outcomes = [a.request_refund('C-1', f'T-{n}', '100.00')['outcome'] for n in range(1004, 1010)]
    # five x $100 = $500 allowed, the sixth must be denied
    return outcomes == ['approved'] * 5 + ['denied'], outcomes


def chain_rt04_replay_same_transaction():
    a = RefundAuthority()
    first = a.request_refund('C-1', 'T-1002', '80.00')['outcome']
    second = a.request_refund('C-1', 'T-1002', '80.00')['outcome']
    return (first, second) == ('approved', 'denied'), [first, second]


def chain_rt05_revocation_blocks_all_refunds():
    a = RefundAuthority()
    before = a.request_refund('C-1', 'T-1002', '80.00')['outcome']
    a.kill_switch(True)
    after = [a.request_refund('C-1', 'T-1004', '10.00')['outcome'],
             a.request_refund('C-1', 'T-1005', '100.00')['outcome']]
    a.kill_switch(False)
    restored = a.request_refund('C-1', 'T-1004', '10.00')['outcome']
    return (before, after, restored) == ('approved', ['denied', 'denied'], 'approved'), \
        {'before': before, 'while_revoked': after, 'after_restore': restored}


def chain_rt06_cross_customer_refund():
    a = RefundAuthority()
    res = a.request_refund('C-1', 'T-1003', '50.00')   # T-1003 belongs to C-2
    unknown = a.request_refund('C-1', 'T-9999', '10.00')
    return res['outcome'] == 'denied' and unknown['outcome'] == 'denied', [res, unknown]


def chain_rt07_weekly_window_rollover():
    t = [datetime(2026, 11, 1, tzinfo=timezone.utc)]
    a = RefundAuthority(now=lambda: t[0])
    for n in range(1004, 1009):
        a.request_refund('C-1', f'T-{n}', '100.00')
    same_day = a.request_refund('C-1', 'T-1009', '1.00')['outcome']
    t[0] += timedelta(days=6, hours=23)       # still inside the 7-day window
    just_inside = a.request_refund('C-1', 'T-1009', '1.00')['outcome']
    t[0] += timedelta(hours=2)                # window has rolled over
    after = a.request_refund('C-1', 'T-1009', '1.00')['outcome']
    return (same_day, just_inside, after) == ('denied', 'denied', 'approved'), \
        [same_day, just_inside, after]


def chain_rt08_overrefund_and_audit_completeness():
    a = RefundAuthority()
    over = a.request_refund('C-1', 'T-1002', '80.01')       # exceeds original $80
    n = len(a.audit)
    a.request_refund('C-1', 'T-1002', '80.00')
    a.kill_switch(True)
    a.request_refund('C-1', 'T-1004', '5.00')
    complete = len(a.audit) == n + 3                         # every attempt + kill switch logged
    return over['outcome'] == 'denied' and complete, {'over': over, 'audit_entries': len(a.audit)}


CHAINS = [
    ('RT-02', 'Per-transaction cap and malformed amounts', chain_rt02_amount_boundaries),
    ('RT-03', 'Split refunds to evade weekly cap', chain_rt03_split_to_evade_weekly_cap),
    ('RT-04', 'Replay a refund on the same transaction', chain_rt04_replay_same_transaction),
    ('RT-05', 'Refund after authority is revoked (kill switch)', chain_rt05_revocation_blocks_all_refunds),
    ('RT-06', "Refund another customer's transaction", chain_rt06_cross_customer_refund),
    ('RT-07', 'Weekly window boundary and rollover', chain_rt07_weekly_window_rollover),
    ('RT-08', 'Over-refund and audit completeness', chain_rt08_overrefund_and_audit_completeness),
]


def main():
    results = []
    for rid, name, fn in CHAINS:
        passed, detail = fn()
        results.append({'id': rid, 'name': name, 'control_held': bool(passed), 'detail': detail})
        print(f"{rid} {'PASS' if passed else 'FAIL'}  {name}")
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = os.path.join(out_dir, f'refund_chains_{ts}.json')
    with open(path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f'evidence: {path}')
    return 0 if all(r['control_held'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
