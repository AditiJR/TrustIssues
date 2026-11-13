"""Small vector database on SQLite (stdlib only).

Documents live in named collections ('policies', 'cases', ...). Each has text, a JSON metadata
object and an embedding. The security property that matters most here (OWASP LLM08/LLM09,
RT-26 and RT-29): metadata filters run inside SQL *before* similarity scoring. A query scoped to
customer C-1 never loads, scores or returns a C-2 document, however similar its text is. There is
no way to search a collection that requires a filter without giving one (see require_filter_on).

Filters are exact matches:
    where={'customer_id': 'C-1'}                     equality
    where={'status': {'$in': ['approved', 'active']}} membership
    where={'customer_id': None}                      key is null or missing
"""
import json
import os
import re
import sqlite3
import threading
import uuid
from array import array
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.rag.embedder import default_embedder

_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,40}$')

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents(
  doc_id TEXT PRIMARY KEY,
  collection TEXT NOT NULL,
  text TEXT NOT NULL,
  metadata TEXT NOT NULL,
  embedding BLOB NOT NULL,
  embedder TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS documents_collection ON documents(collection);
"""


class ScopeRequired(ValueError):
    """Raised when a collection that must be filtered is queried without the required filter keys."""


@dataclass
class Hit:
    doc_id: str
    text: str
    metadata: dict
    score: float
    collection: str = ''
    extra: dict = field(default_factory=dict)

    def to_chunk(self):
        """Shape Blake's access_control.filter_chunks() expects: tags at top level and under metadata."""
        return {'id': self.doc_id, 'text': self.text, 'score': round(self.score, 4),
                'customer_id': self.metadata.get('customer_id'),
                'transaction_id': self.metadata.get('transaction_id'),
                'metadata': dict(self.metadata), **self.extra}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _pack(vec):
    return array('f', vec).tobytes()


def _unpack(blob):
    a = array('f')
    a.frombytes(blob)
    return a


class VectorStore:
    def __init__(self, path=':memory:', embedder=None):
        self.path = path
        self.embedder = embedder or default_embedder()
        self._lock = threading.RLock()
        if path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.execute('PRAGMA foreign_keys = ON')
        if path != ':memory:':
            self.conn.execute('PRAGMA journal_mode = WAL')
        self.conn.executescript(SCHEMA)
        self._required = {}   # collection -> tuple of keys every query must filter on

    def require_filter_on(self, collection, *keys):
        """Every query on this collection must filter on all of these keys (tenant isolation)."""
        self._required[collection] = tuple(keys)

    # -------------------------------------------------------------- writes
    def add(self, collection, text, metadata=None, *, doc_id=None):
        if not isinstance(text, str) or not text.strip():
            raise ValueError('text must be a non-empty string')
        metadata = dict(metadata or {})
        for k in metadata:
            if not _KEY.match(k):
                raise ValueError('bad metadata key %r' % k)
        doc_id = doc_id or uuid.uuid4().hex
        now = _now()
        with self._lock:
            self.conn.execute(
                'INSERT INTO documents(doc_id, collection, text, metadata, embedding, embedder, created_at, updated_at) '
                'VALUES (?,?,?,?,?,?,?,?)',
                (doc_id, collection, text, json.dumps(metadata, sort_keys=True), _pack(self.embedder.embed(text)),
                 self.embedder.name, now, now))
        return doc_id

    def update(self, collection, doc_id, *, text=None, metadata=None, merge=True):
        """Change text (re-embedded) and/or metadata. Returns False if the document does not exist."""
        with self._lock:
            row = self.conn.execute('SELECT text, metadata FROM documents WHERE collection = ? AND doc_id = ?',
                                    (collection, doc_id)).fetchone()
            if row is None:
                return False
            new_text = text if text is not None else row[0]
            meta = json.loads(row[1]) if merge else {}
            if metadata:
                for k in metadata:
                    if not _KEY.match(k):
                        raise ValueError('bad metadata key %r' % k)
                meta.update(metadata)
            self.conn.execute('UPDATE documents SET text = ?, metadata = ?, embedding = ?, embedder = ?, updated_at = ? '
                              'WHERE collection = ? AND doc_id = ?',
                              (new_text, json.dumps(meta, sort_keys=True), _pack(self.embedder.embed(new_text)),
                               self.embedder.name, _now(), collection, doc_id))
            return True

    def delete(self, collection, where):
        if not where:
            raise ValueError('delete needs a filter')
        sql, args = self._where(collection, where)
        with self._lock:
            return self.conn.execute('DELETE FROM documents WHERE ' + sql, args).rowcount

    # -------------------------------------------------------------- reads
    def _where(self, collection, where):
        clauses, args = ['collection = ?'], [collection]
        for key, val in (where or {}).items():
            if not _KEY.match(key):
                raise ValueError('bad filter key %r' % key)
            path = "json_extract(metadata, '$.%s')" % key     # key is checked against _KEY above
            if isinstance(val, dict) and set(val) == {'$in'}:
                vals = list(val['$in'])
                if not vals:
                    clauses.append('0')
                    continue
                clauses.append('%s IN (%s)' % (path, ','.join('?' * len(vals))))
                args.extend(int(v) if isinstance(v, bool) else v for v in vals)
            elif val is None:
                clauses.append('%s IS NULL' % path)
            elif isinstance(val, (str, int, float, bool)):
                clauses.append('%s = ?' % path)
                args.append(int(val) if isinstance(val, bool) else val)
            else:
                raise ValueError('unsupported filter value for %r' % key)
        return ' AND '.join(clauses), args

    def _check_scope(self, collection, where):
        need = self._required.get(collection, ())
        missing = [k for k in need if k not in (where or {}) or where[k] is None]
        if missing:
            raise ScopeRequired('collection %r must be filtered on %s' % (collection, ', '.join(missing)))

    def get(self, collection, doc_id):
        row = self.conn.execute('SELECT doc_id, text, metadata FROM documents WHERE collection = ? AND doc_id = ?',
                                (collection, doc_id)).fetchone()
        return Hit(row[0], row[1], json.loads(row[2]), 1.0, collection) if row else None

    def find(self, collection, where=None, *, limit=1000):
        """Metadata lookup without similarity (ordered by creation time)."""
        self._check_scope(collection, where)
        sql, args = self._where(collection, where)
        rows = self.conn.execute('SELECT doc_id, text, metadata FROM documents WHERE %s ORDER BY created_at, rowid '
                                 'LIMIT ?' % sql, args + [limit]).fetchall()
        return [Hit(r[0], r[1], json.loads(r[2]), 1.0, collection) for r in rows]

    def count(self, collection, where=None):
        sql, args = self._where(collection, where)
        return self.conn.execute('SELECT COUNT(*) FROM documents WHERE ' + sql, args).fetchone()[0]

    def query(self, collection, query_text, *, k=4, where=None, min_score=0.0):
        """Top-k documents by cosine similarity among those matching `where`."""
        self._check_scope(collection, where)
        if not isinstance(query_text, str) or not query_text.strip():
            return []
        q = self.embedder.embed(query_text)
        sql, args = self._where(collection, where)
        with self._lock:
            rows = self.conn.execute('SELECT doc_id, text, metadata, embedding, embedder FROM documents WHERE ' + sql,
                                     args).fetchall()
        hits = []
        for doc_id, text, meta, blob, emb_name in rows:
            if emb_name != self.embedder.name:
                continue          # vectors from another embedder are not comparable
            vec = _unpack(blob)
            score = sum(a * b for a, b in zip(q, vec))
            if score >= min_score:
                hits.append(Hit(doc_id, text, json.loads(meta), score, collection))
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:max(0, int(k))]
