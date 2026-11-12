"""Policy store: versioned refund policies in the vector DB.

Admin workflow from the proposal (section 3.5):
  upload   -> the document is chunked, every chunk is scanned by the detector, embedded and
              stored with a version number. Chunks that carry instructions to the agent, or that
              state a refund limit higher than the coded limits, are quarantined: stored for the
              investigator but never retrieved (RT-13, RT-17, RT-27).
  retrieve -> only chunks from the latest approved version of each document. Every result has
              provenance (document, version, section, chunk id, sha256) and every retrieval is
              logged, so the admin can see which passages informed each decision.
  approve  -> uploads can be held as 'pending' and approved later. Approving a version marks
              the previous approved version of the same document 'superseded'.

A policy upload never changes the limits. They are code constants (Blake's limit control).
"""
import hashlib
import re
from datetime import datetime, timezone

from app.monitoring.audit import get_audit_log
from app.monitoring.detection import Finding, get_detector

try:   # use Blake's constants once his branch is merged, so there is one source of truth
    from app.controls.limits import PER_TXN_LIMIT_CENTS, WEEKLY_LIMIT_CENTS
    PER_TXN_LIMIT, WEEKLY_LIMIT = PER_TXN_LIMIT_CENTS / 100, WEEKLY_LIMIT_CENTS / 100
except ImportError:
    PER_TXN_LIMIT, WEEKLY_LIMIT = 100.0, 500.0

COLLECTION = 'policies'
# besides anything malicious: limit conflicts, and internal-only material (canaries, INTERNAL ONLY),
# which must never sit in a store whose passages can reach customer-facing replies (RT-20)
QUARANTINE_RULES = frozenset({'POLICY-LIMIT-CONFLICT', 'CANARY'})
DEFAULT_DOC = 'refund-policy'
MAX_CHUNK = 700
MAX_DOC_CHARS = 200_000
_NAME = re.compile(r'^[a-z0-9][a-z0-9:._-]{0,63}$')

SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_versions(
  doc_name TEXT NOT NULL, version INTEGER NOT NULL, title TEXT NOT NULL, text TEXT NOT NULL,
  sha256 TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','superseded','rejected')),
  uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT,
  chunk_count INTEGER NOT NULL, quarantined_count INTEGER NOT NULL,
  PRIMARY KEY (doc_name, version));
"""

_MONEY = re.compile(r'\$\s?(\d[\d,]*(?:\.\d{1,2})?)')
_LIMIT_CTX = re.compile(r'\b(limit|cap|maximum|max|up to|no more than|at most|ceiling|threshold|approve)\b', re.I)
_WEEK_CTX = re.compile(r'\b(week|weekly|seven day|7 day|7-day)\b', re.I)


def _now():
    return datetime.now(timezone.utc).isoformat()


def chunk_document(text, max_chars=MAX_CHUNK):
    """Split on markdown headings, then paragraphs. Each chunk keeps its section heading so it
    still makes sense on its own when retrieved. Returns [(section, chunk_text)]."""
    sections, current, buf = [], 'Preamble', []
    for line in text.splitlines():
        m = re.match(r'^\s{0,3}#{1,6}\s+(.*)$', line)
        if m:
            if any(s.strip() for s in buf):
                sections.append((current, '\n'.join(buf).strip()))
            current, buf = m.group(1).strip() or current, []
        else:
            buf.append(line)
    if any(s.strip() for s in buf):
        sections.append((current, '\n'.join(buf).strip()))

    chunks = []
    for section, body in sections:
        paras = [p.strip() for p in re.split(r'\n\s*\n', body) if p.strip()]
        piece = ''
        for p in paras:
            while len(p) > max_chars:                       # very long paragraph: split on sentences
                cut = p.rfind('. ', 0, max_chars)
                cut = cut + 1 if cut > max_chars // 3 else max_chars
                if piece:
                    chunks.append((section, piece))
                    piece = ''
                chunks.append((section, p[:cut].strip()))
                p = p[cut:].strip()
            if piece and len(piece) + len(p) + 2 > max_chars:
                chunks.append((section, piece))
                piece = p
            else:
                piece = (piece + '\n\n' + p).strip()
        if piece:
            chunks.append((section, piece))
    return [(s, '%s\n%s' % (s, c)) for s, c in chunks]


def limit_conflicts(text):
    """Findings for any dollar amount stated as a limit that is higher than the coded limits."""
    out = []
    for m in _MONEY.finditer(text):
        try:
            amount = float(m.group(1).replace(',', ''))
        except ValueError:
            continue
        ctx = text[max(0, m.start() - 70):m.end() + 70]
        if not _LIMIT_CTX.search(ctx):
            continue
        cap = WEEKLY_LIMIT if _WEEK_CTX.search(ctx) else PER_TXN_LIMIT
        if amount > cap:
            out.append(Finding('POLICY-LIMIT-CONFLICT', 'excessive_agency', ['LLM03', 'ASI03'],
                               'L6 Security & Compliance', 'high',
                               'Policy text states a limit above the coded limit ($%.0f per refund, $%.0f per week)'
                               % (PER_TXN_LIMIT, WEEKLY_LIMIT), 'text', ctx.replace('\n', ' ')[:120]))
    return out


class PolicyStore:
    def __init__(self, vector_store, detector=None, audit=None):
        self.vs = vector_store
        self.detector = detector or get_detector()
        self._audit = audit
        self.vs.conn.executescript(SCHEMA)

    @property
    def audit(self):
        return self._audit or get_audit_log()

    # -------------------------------------------------------------- admin side
    def upload(self, text, *, title=None, doc_name=DEFAULT_DOC, uploaded_by='admin', approve=True):
        """Chunk, scan, embed and store a new version. Returns a summary (no policy text)."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError('policy text is empty')
        if len(text) > MAX_DOC_CHARS:
            raise ValueError('policy text is too long')
        if not _NAME.match(doc_name or ''):
            raise ValueError('doc_name must be lowercase letters, digits, and : . _ -')
        title = (title or doc_name)[:120]
        sha = hashlib.sha256(text.encode('utf-8')).hexdigest()
        with self.vs._lock:
            row = self.vs.conn.execute('SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE doc_name = ?',
                                       (doc_name,)).fetchone()
            version = row[0] + 1
            quarantined, n = [], 0
            for idx, (section, chunk) in enumerate(chunk_document(text)):
                scan = self.detector.scan_retrieved(chunk, source='policy_upload', log=False)
                findings = scan.findings + limit_conflicts(chunk)
                bad = scan.malicious or any(f.rule_id in QUARANTINE_RULES for f in findings)
                rule_ids = sorted({f.rule_id for f in findings})
                meta = {'doc_type': 'policy', 'doc_name': doc_name, 'version': version, 'title': title,
                        'section': section[:80], 'chunk_index': idx, 'status': 'pending',
                        'quarantined': bool(bad), 'rule_ids': rule_ids, 'customer_id': None,
                        'sha256': hashlib.sha256(chunk.encode('utf-8')).hexdigest()}
                chunk_id = 'POL-%s-v%d-c%02d' % (doc_name, version, idx)
                self.vs.add(COLLECTION, chunk, meta, doc_id=chunk_id)
                n += 1
                if bad:
                    quarantined.append({'chunk_id': chunk_id, 'section': section[:80], 'rule_ids': rule_ids})
                    self.audit.log('policy_store', 'policy_chunk_quarantined', severity='high', actor_detail=uploaded_by,
                                   doc_name=doc_name, version=version, chunk_id=chunk_id, rule_ids=rule_ids,
                                   findings=[{'rule_id': f.rule_id, 'evidence': f.evidence} for f in findings],
                                   owasp=sorted({o for f in findings for o in f.owasp}))
            self.vs.conn.execute('INSERT INTO policy_versions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                 (doc_name, version, title, text, sha, 'pending', uploaded_by, _now(), None, None,
                                  n, len(quarantined)))
        self.audit.log('policy_store', 'policy_uploaded', severity='medium' if quarantined else 'info',
                       uploaded_by=uploaded_by, doc_name=doc_name, version=version, sha256=sha, chunks=n,
                       quarantined=len(quarantined))
        if approve:
            self.approve(version, doc_name=doc_name, approved_by=uploaded_by)
        return {'doc_name': doc_name, 'version': version, 'title': title, 'sha256': sha, 'chunks': n,
                'quarantined': quarantined, 'status': 'approved' if approve else 'pending'}

    def approve(self, version, *, doc_name=DEFAULT_DOC, approved_by='admin'):
        with self.vs._lock:
            row = self.vs.conn.execute('SELECT status FROM policy_versions WHERE doc_name = ? AND version = ?',
                                       (doc_name, version)).fetchone()
            if row is None:
                raise KeyError('no such policy version')
            if row[0] != 'pending':
                raise ValueError('only a pending version can be approved (this one is %s)' % row[0])
            now = _now()
            self.vs.conn.execute("UPDATE policy_versions SET status = 'superseded' WHERE doc_name = ? AND status = 'approved'",
                                 (doc_name,))
            self.vs.conn.execute("UPDATE policy_versions SET status = 'approved', approved_by = ?, approved_at = ? "
                                 "WHERE doc_name = ? AND version = ?", (approved_by, now, doc_name, version))
            for hit in self.vs.find(COLLECTION, {'doc_name': doc_name}):
                v = hit.metadata.get('version')
                status = 'approved' if v == version else ('superseded' if hit.metadata.get('status') == 'approved'
                                                          else hit.metadata.get('status'))
                if status != hit.metadata.get('status'):
                    self.vs.update(COLLECTION, hit.doc_id, metadata={'status': status})
        self.audit.log('policy_store', 'policy_approved', approved_by=approved_by, doc_name=doc_name, version=version)
        return self.version_info(version, doc_name=doc_name)

    def reject(self, version, *, doc_name=DEFAULT_DOC, rejected_by='admin'):
        with self.vs._lock:
            n = self.vs.conn.execute("UPDATE policy_versions SET status = 'rejected' WHERE doc_name = ? AND version = ? "
                                     "AND status = 'pending'", (doc_name, version)).rowcount
            if n:
                for hit in self.vs.find(COLLECTION, {'doc_name': doc_name, 'version': version}):
                    self.vs.update(COLLECTION, hit.doc_id, metadata={'status': 'rejected'})
        self.audit.log('policy_store', 'policy_rejected', rejected_by=rejected_by, doc_name=doc_name, version=version,
                       changed=bool(n))
        return bool(n)

    def list_versions(self, doc_name=None):
        sql = ('SELECT doc_name, version, title, sha256, status, uploaded_by, uploaded_at, approved_by, approved_at, '
               'chunk_count, quarantined_count FROM policy_versions')
        args = ()
        if doc_name:
            sql += ' WHERE doc_name = ?'
            args = (doc_name,)
        cols = ['doc_name', 'version', 'title', 'sha256', 'status', 'uploaded_by', 'uploaded_at', 'approved_by',
                'approved_at', 'chunks', 'quarantined']
        return [dict(zip(cols, r)) for r in self.vs.conn.execute(sql + ' ORDER BY doc_name, version', args).fetchall()]

    def version_info(self, version, *, doc_name=DEFAULT_DOC):
        return next((v for v in self.list_versions(doc_name) if v['version'] == version), None)

    def get_document(self, version=None, *, doc_name=DEFAULT_DOC):
        """Full text of a version (default: the approved one), for the admin download."""
        if version is None:
            row = self.vs.conn.execute("SELECT version, title, text, status FROM policy_versions WHERE doc_name = ? "
                                       "AND status = 'approved'", (doc_name,)).fetchone()
        else:
            row = self.vs.conn.execute('SELECT version, title, text, status FROM policy_versions WHERE doc_name = ? '
                                       'AND version = ?', (doc_name, version)).fetchone()
        return dict(zip(['version', 'title', 'text', 'status'], row)) if row else None

    def quarantined_chunks(self):
        return [{'chunk_id': h.doc_id, 'doc_name': h.metadata.get('doc_name'), 'version': h.metadata.get('version'),
                 'section': h.metadata.get('section'), 'rule_ids': h.metadata.get('rule_ids')}
                for h in self.vs.find(COLLECTION, {'quarantined': True})]

    # -------------------------------------------------------------- agent side
    def retrieve(self, query, *, k=3, min_score=0.05, case_id=None, actor='retriever'):
        """Top passages from approved, non-quarantined chunks. Each one is scanned again on the way out
        (defence in depth: catches a chunk written straight into the DB, or a rule added later)."""
        hits = self.vs.query(COLLECTION, query, k=k + 3, min_score=min_score,
                             where={'status': 'approved', 'quarantined': False})
        kept, dropped = [], []
        for h in hits:
            scan = self.detector.scan_retrieved(h.text, source='policy_retrieval', case_id=case_id,
                                                extra={'chunk_id': h.doc_id})
            if scan.malicious or QUARANTINE_RULES & set(scan.rule_ids):
                dropped.append({'chunk_id': h.doc_id, 'rule_ids': scan.rule_ids})
                continue
            h.extra = {'provenance': {'doc_name': h.metadata.get('doc_name'), 'version': h.metadata.get('version'),
                                      'section': h.metadata.get('section'), 'chunk_id': h.doc_id,
                                      'sha256': h.metadata.get('sha256')},
                       'scan_verdict': scan.verdict}
            kept.append(h.to_chunk())
            if len(kept) >= k:
                break
        self.audit.log(actor, 'policy_retrieval', case_id=case_id, severity='high' if dropped else 'info',
                       query_sha256=hashlib.sha256(query.encode('utf-8', 'replace')).hexdigest(),
                       query_excerpt=query[:120],
                       returned=[{'chunk_id': c['id'], 'version': c['metadata'].get('version'), 'score': c['score']}
                                 for c in kept],
                       dropped=dropped)
        return kept


def format_context(chunks):
    """Passages as one string for an LLM prompt, each tagged with its provenance and wrapped so the
    model can tell retrieved data from instructions."""
    parts = []
    for c in chunks:
        p = c.get('provenance', {})
        body = c['text'].replace('<', '&lt;')    # retrieved text cannot close the tag and pose as instructions
        parts.append('<policy_passage doc="%s" version="%s" chunk="%s">%s</policy_passage>'
                     % (p.get('doc_name'), p.get('version'), p.get('chunk_id'), body))
    return '\n'.join(parts)
