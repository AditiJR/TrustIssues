"""Runs every blue-team control check as a unit test.

  python3 -m unittest discover -s tests

The checks themselves live in blueteam/run_retest.py so the same code produces the retest evidence.
"""
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, ROOT)

from blueteam import run_retest  # noqa: E402


class ControlChecks(unittest.TestCase):
    pass


def _make(check):
    def test(self):
        held, detail = check['fn'](run_retest.Target())
        self.assertTrue(held, '%s: %s' % (check['id'], detail))
    test.__doc__ = '%s %s' % (check['id'], check['name'])
    return test


for _c in run_retest.CHECKS:
    setattr(ControlChecks, 'test_' + _c['id'].lower().replace('-', '_'), _make(_c))


if __name__ == '__main__':
    unittest.main()
