#!/usr/bin/env python3
"""Run the red team's own harnesses, unmodified, from a git ref, against the controls in this tree.

  python3 blueteam/run_redteam.py --ref origin/redteam1
  python3 blueteam/run_redteam.py --ref origin/redteam-nagashree --python .venv/bin/python

The red team's redteam/ directory is extracted from the ref into a temp dir. For that process only,
app.refund is aliased to app.controls.authority, so `from app.refund import RefundAuthority` reaches the
real limit control. Their evidence files are copied next to ours, prefixed with the red commit.
"""
import argparse
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SHIM = ("import sys, runpy; sys.path.insert(0, sys.argv[1]); import app.controls.authority as m; "
        "sys.modules['app.refund'] = m; import app; app.refund = m; script = sys.argv[2]; sys.argv = [script]; "
        "runpy.run_path(script, run_name='__main__')")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ref', default='origin/redteam1')
    ap.add_argument('--python', default=sys.executable, help='interpreter for the red harness (one with fastapi for the HTTP chains)')
    ap.add_argument('--out', default=os.path.join(ROOT, 'blueteam', 'evidence'))
    args = ap.parse_args()
    if os.sep in args.python:
        args.python = os.path.abspath(args.python)      # the harness runs from a temp dir (keep venv symlinks intact)
    sha = subprocess.run(['git', '-C', ROOT, 'rev-parse', args.ref], capture_output=True, text=True, check=True).stdout.strip()
    blob = subprocess.run(['git', '-C', ROOT, 'archive', sha, 'redteam'], capture_output=True, check=True).stdout
    tmp = tempfile.mkdtemp(prefix='redteam_at_')
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        if hasattr(tarfile, 'data_filter'):
            tar.extractall(tmp, filter='data')
        else:
            tar.extractall(tmp)
    before = set(glob.glob(os.path.join(tmp, 'redteam', 'results', '*.json')))
    runs = []
    scripts = sorted(glob.glob(os.path.join(tmp, 'redteam', 'run_*_chains.py')))
    for script in scripts:
        # the red harness always gets its own scratch store, never the live one
        env = {**os.environ, 'PYTHONPATH': ROOT, 'PYTHONDONTWRITEBYTECODE': '1',
               'TRUSTISSUES_CONTROL_DB': os.path.join(tmp, 'controls.db')}
        p = subprocess.run([args.python, '-c', SHIM, ROOT, script], capture_output=True, text=True, cwd=tmp, env=env)
        lines = [line for line in p.stdout.splitlines() if line.startswith('RT-')]
        source = open(script, encoding='utf-8', errors='replace').read()
        target = ('app.controls.authority (aliased as app.refund)' if 'app.refund' in source
                  else 'app.main and starter modules in this tree')
        runs.append({'script': os.path.basename(script), 'target': target, 'exit_code': p.returncode, 'lines': lines,
                     'stderr_tail': p.stderr[-300:]})
        print(os.path.basename(script), 'exit', p.returncode)
        for line in lines:
            print('  ', line)
    os.makedirs(args.out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    copied = []
    for f in sorted(set(glob.glob(os.path.join(tmp, 'redteam', 'results', '*.json'))) - before):
        name = 'redteam_' + sha[:7] + '_' + os.path.basename(f)
        shutil.copy(f, os.path.join(args.out, name))
        copied.append(name)
    path = os.path.join(args.out, f'redteam_run_{sha[:7]}_{ts}.json')
    status = 'no_scripts' if not runs else ('all_passed' if all(r['exit_code'] == 0 for r in runs) else 'failures')
    with open(path, 'x') as fh:
        version = subprocess.run([args.python, '--version'], capture_output=True, text=True).stdout.strip()
        json.dump({'run_at': ts, 'red_ref': args.ref, 'red_commit': sha, 'python': version, 'status': status,
                   'runs': runs, 'red_evidence': copied}, fh, indent=2)
    print('evidence:', path)
    shutil.rmtree(tmp, ignore_errors=True)
    if not runs:
        print('no redteam/run_*_chains.py at', args.ref, file=sys.stderr)
    return 0 if status == 'all_passed' else 1


if __name__ == '__main__':
    sys.exit(main())
