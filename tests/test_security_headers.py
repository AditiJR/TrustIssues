"""security headers on every response, and no /docs, /redoc or /openapi.json on vercel."""
import base64
import hashlib
import importlib
import os
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient

INDEX = os.path.join(os.path.dirname(__file__), '..', 'app', 'static', 'index.html')
DOCS = ('/docs', '/redoc', '/openapi.json')


@pytest.fixture(autouse=True)
def temp_dbs(isolated_paths, monkeypatch):
    # the refund route runs the rate limiter and the admin 403 gets audited by the gate, so without this
    # both write to the real logs/casework.db and logs/controls.db
    from app import ratelimit
    from app.controls import gate
    monkeypatch.setenv('TRUSTISSUES_CONTROL_DB', str(isolated_paths / 'controls.db'))
    monkeypatch.setenv('TRUSTISSUES_CASEWORK_DB', str(isolated_paths / 'casework.db'))
    gate._reset_for_tests()
    ratelimit._reset_for_tests()
    yield
    gate._reset_for_tests()
    ratelimit._reset_for_tests()


@pytest.fixture
def client(isolated_paths, monkeypatch):
    monkeypatch.delenv('VERCEL', raising=False)
    import app.main as main
    monkeypatch.setattr(main, 'LOG_DIR', str(isolated_paths))
    return TestClient(main.app)


@pytest.fixture
def vercel_client(isolated_paths, monkeypatch):
    # the docs urls are fixed when the app is built, so rebuild it with VERCEL set, then rebuild it again after
    import app.main as main
    monkeypatch.setenv('VERCEL', '1')
    importlib.reload(main)
    monkeypatch.setattr(main, 'LOG_DIR', str(isolated_paths))
    yield TestClient(main.app)
    monkeypatch.delenv('VERCEL')
    importlib.reload(main)


def _assert_headers(r, csp=True):
    assert r.headers['x-content-type-options'] == 'nosniff'
    assert r.headers['x-frame-options'] == 'DENY'
    assert r.headers['referrer-policy'] == 'no-referrer'
    assert r.headers['strict-transport-security'].startswith('max-age=')
    if csp:
        assert "default-src 'none'" in r.headers['content-security-policy']


@pytest.mark.parametrize('method,path,status', [
    ('get', '/', 200),
    ('get', '/static/index.html', 200),
    ('post', '/api/refund-requests', 422),     # error responses get them too
    ('get', '/admin/audit', 403),
    ('get', '/nope', 404),
])
def test_headers_on_every_response(client, method, path, status):
    r = client.request(method.upper(), path, json={})
    assert r.status_code == status
    _assert_headers(r)


class _InlineBlocks(HTMLParser):
    """collects the text of inline <script> and <style> blocks, the way a browser hashes them."""

    def __init__(self):
        super().__init__()
        self.blocks, self._tag = {'script': [], 'style': []}, None

    def handle_starttag(self, tag, attrs):
        if tag in self.blocks:
            self._tag = tag
            self.blocks[tag].append('')

    def handle_endtag(self, tag):
        self._tag = None

    def handle_data(self, data):
        if self._tag:
            self.blocks[self._tag][-1] += data


def test_csp_allows_exactly_the_page_inline_blocks(client):
    with open(INDEX, encoding='utf-8') as fh:
        parser = _InlineBlocks()
        parser.feed(fh.read())
    csp = dict(d.split(' ', 1) for d in client.get('/').headers['content-security-policy'].split('; '))
    assert 'unsafe-inline' not in str(csp) and 'unsafe-eval' not in str(csp)
    for tag, directive in (('script', 'script-src'), ('style', 'style-src')):
        want = {"'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode()
                for b in parser.blocks[tag]}
        assert want and set(csp[directive].split()) == want
    assert csp['frame-ancestors'] == "'none'"


def test_docs_on_locally(client):
    for path in DOCS:
        assert client.get(path).status_code == 200
    r = client.get('/docs')
    _assert_headers(r, csp=False)
    assert 'content-security-policy' not in r.headers     # swagger needs its cdn


def test_docs_off_on_vercel(vercel_client):
    for path in DOCS + ('/docs/oauth2-redirect',):
        r = vercel_client.get(path)
        assert r.status_code == 404
        _assert_headers(r)
    assert vercel_client.get('/').status_code == 200
