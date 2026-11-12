"""in-memory kill switch for the orchestrator.

once it's revoked it stays revoked until the server restarts. there's literally no way to re-enable it at runtime, so just don't.
there's no admin login yet (i'll add it), so a re-enable endpoint would let anyone undo a revoke.
"""

import threading


class KillSwitch:
    def __init__(self):
        self._lock = threading.Lock()
        self._revoked = False
        self._reason = None

    def revoke(self, reason: str) -> bool:
        # returns False if it was already revoked, so the log can tell a repeat revoke apart
        with self._lock:
            if self._revoked:
                return False
            self._revoked = True
            self._reason = reason
            return True

    def is_revoked(self) -> bool:
        with self._lock:
            return self._revoked

    def status(self) -> dict:
        with self._lock:
            return {'revoked': self._revoked, 'reason': self._reason}
