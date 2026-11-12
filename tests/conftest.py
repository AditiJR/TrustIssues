import json
import os

import pytest

from app.monitoring.audit import AuditLog
from app.monitoring.detection import Detector

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.fixture(autouse=True)
def isolated_paths(tmp_path, monkeypatch):
    """Every test gets its own event log and RAG database, never the repo's logs/."""
    monkeypatch.setenv('TRUSTISSUES_EVENT_LOG', str(tmp_path / 'events.jsonl'))
    monkeypatch.setenv('TRUSTISSUES_RAG_DB', str(tmp_path / 'rag.db'))
    yield tmp_path


@pytest.fixture
def audit(tmp_path):
    return AuditLog(str(tmp_path / 'events.jsonl'))


@pytest.fixture
def detector(audit):
    return Detector(audit=audit)


@pytest.fixture
def stores(audit, detector):
    from app.rag import build
    return build(':memory:', detector=detector, audit=audit)


@pytest.fixture(scope='session')
def payloads():
    """Nagashree's synthetic red-team payloads (copied from redteam/testdata/input_email_payloads.json)."""
    with open(os.path.join(FIXTURES, 'redteam_input_email_payloads.json')) as fh:
        return json.load(fh)
