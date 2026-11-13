"""Policy retriever backed by the vector DB (replaces the starter's keyword lookup).

The starter mapped a keyword in the task name to one canned sentence, so any text containing
'expense' pulled the expense policy (RT-16), and anything planted in the dict came back verbatim
(RT-17, RT-20). Now:

  * search() embeds the query and returns the top passages from the latest approved policy
    version, each with provenance (document, version, section, chunk id, sha256).
  * Chunks were scanned at upload and are scanned again on retrieval. Anything carrying
    instructions to the agent is dropped before it reaches a prompt.
  * Every retrieval is logged with the chunk ids returned, so a decision can be traced back to the
    exact passages it used.

get_context() keeps the starter signature (str in, str or None out) so app/agent.py still works.

Compatibility with the red-team harness: the starter exposed `retriever.store` as a dict and the
RT-17/RT-20 chains plant poisoned text with `retriever.store['refund'] = text`. That still works,
but it now goes through the real upload path on a private in-memory copy of the policy store, so
the shared database is never touched and the planted text is scanned like any other upload.
"""
from app.rag import build, get_policy_store
from app.rag.policy_store import format_context


class _LegacyStore(dict):
    """dict that turns `store[key] = text` into a policy upload on the retriever's private store."""

    def __init__(self, retriever):
        super().__init__()
        self._r = retriever

    def __setitem__(self, key, text):
        super().__setitem__(key, text)
        self._r._private_store().upload(text, title='legacy:%s' % key, doc_name='legacy-%s' % str(key).lower()[:40],
                                        uploaded_by='legacy-store-adapter', approve=True)


class Retriever:
    def __init__(self, policy_store=None, *, k=3, min_score=0.12):
        self._ps = policy_store
        self.k = k
        self.min_score = min_score
        self.store = _LegacyStore(self)
        self.last_results = []

    @property
    def policy_store(self):
        return self._ps or get_policy_store()

    def _private_store(self):
        if not getattr(self, '_private', False):
            self._ps = build(':memory:')[1]
            self._private = True
        return self._ps

    def search(self, query, *, k=None, case_id=None):
        """List of passages (dicts with text, score, provenance). Empty if nothing is relevant enough."""
        self.last_results = self.policy_store.retrieve(query or '', k=k or self.k, min_score=self.min_score,
                                                       case_id=case_id)
        return self.last_results

    def get_context(self, key, *, case_id=None):
        """Starter-compatible: the relevant passages as one string, or None."""
        hits = self.search(key, case_id=case_id)
        if not hits:
            return None
        return '\n\n'.join('[%s v%s, %s] %s' % (h['provenance']['doc_name'], h['provenance']['version'],
                                                 h['provenance']['section'], h['text'].split('\n', 1)[-1])
                           for h in hits)

    def prompt_context(self, query, *, case_id=None):
        """Passages wrapped in <policy_passage> tags for an LLM prompt (for Sargis's agents)."""
        return format_context(self.search(query, case_id=case_id))
