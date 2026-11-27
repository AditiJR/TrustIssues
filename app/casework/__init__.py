"""case queue, mock mailbox and decision records (Sargis). the agents that write them are in agents.py."""
import threading

from app.casework.store import CaseworkStore, db_path

_lock = threading.Lock()
_state = {}


def get_casework_store():
    """one store per process. rebuilt if the path changes, which only happens in tests."""
    path = db_path()
    with _lock:
        if _state.get('path') != path:
            old = _state.get('store')
            if old is not None:
                old.close()
            _state.update(store=CaseworkStore(path), path=path)
        return _state['store']


def _reset_for_tests():
    with _lock:
        if _state.get('store') is not None:
            _state['store'].close()
        _state.clear()
