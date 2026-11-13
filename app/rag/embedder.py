"""Text embedders for the vector store.

HashingEmbedder (default) runs offline with no model download. It hashes word unigrams,
word bigrams and character 4-grams into a fixed-size vector (the "hashing trick"), with
sublinear term frequency and L2 normalisation, so cosine similarity is a dot product.
It is deterministic, which keeps red-team evidence reproducible run to run.

SentenceTransformerEmbedder is optional. Set TRUSTISSUES_EMBEDDER=sbert and
`pip install sentence-transformers` to use a real semantic model (all-MiniLM-L6-v2 by default,
override with TRUSTISSUES_SBERT_MODEL). It needs network access the first time to download
the model. Switching embedders changes vector sizes, so delete logs/rag.db afterwards and let
it re-seed.
"""
import hashlib
import math
import os
import re

STOPWORDS = frozenset("""a an and are as at be been but by can could did do does for from had has have
he her his i if in into is it its me my of on or our she so than that the their them then there
these they this to too us was we were what when which who will with would you your""".split())

_TOKEN = re.compile(r"[a-z0-9$]+(?:'[a-z]+)?")
_SUFFIXES = ('ingly', 'edly', 'ing', 'ies', 'ied', 'ed', 'es', 's', 'ly')


def stem(word):
    """Very light suffix stripping so refund/refunds/refunded land on the same feature."""
    for suf in _SUFFIXES:
        if len(word) > len(suf) + 2 and word.endswith(suf):
            word = word[: -len(suf)] + ('y' if suf in ('ies', 'ied') else '')
            break
    if len(word) > 4 and word.endswith('e'):          # charge / charged -> charg
        word = word[:-1]
    return word


def tokenize(text):
    return [stem(t) for t in _TOKEN.findall(text.lower()) if t not in STOPWORDS]


class HashingEmbedder:
    name = 'hashing-v1'

    def __init__(self, dim=1024):
        self.dim = dim

    def _bucket(self, feature):
        h = hashlib.blake2b(feature.encode('utf-8'), digest_size=8).digest()
        n = int.from_bytes(h, 'little')
        return n % self.dim, (1.0 if (n >> 63) & 1 else -1.0)

    def embed(self, text):
        counts = {}
        toks = tokenize(text)
        feats = [('w:' + t, 1.0) for t in toks]
        feats += [('b:%s_%s' % (a, b), 0.6) for a, b in zip(toks, toks[1:])]
        for t in toks:
            padded = '^%s$' % t
            feats += [('c:' + padded[i:i + 4], 0.25) for i in range(max(1, len(padded) - 3))]
        for feat, weight in feats:
            counts[feat] = counts.get(feat, 0.0) + weight
        vec = [0.0] * self.dim
        for feat, tf in counts.items():
            idx, sign = self._bucket(feat)
            vec[idx] += sign * (1.0 + math.log(tf)) if tf >= 1 else sign * tf
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else vec


class SentenceTransformerEmbedder:
    """Optional. Not used unless TRUSTISSUES_EMBEDDER=sbert."""

    def __init__(self, model_name=None):
        from sentence_transformers import SentenceTransformer  # imported lazily on purpose
        model_name = model_name or os.environ.get('TRUSTISSUES_SBERT_MODEL', 'all-MiniLM-L6-v2')
        self._model = SentenceTransformer(model_name)
        self.name = 'sbert:' + model_name
        self.dim = self._model.get_sentence_embedding_dimension()

    def embed(self, text):
        return [float(x) for x in self._model.encode(text, normalize_embeddings=True)]


def default_embedder():
    if os.environ.get('TRUSTISSUES_EMBEDDER', '').lower() == 'sbert':
        return SentenceTransformerEmbedder()
    return HashingEmbedder()
