import pytest

from app.rag.embedder import HashingEmbedder, tokenize
from app.rag.vectorstore import VectorStore, ScopeRequired


@pytest.fixture
def vs():
    return VectorStore(':memory:')


def test_similar_text_ranks_higher(vs):
    vs.add('c', 'The item arrived damaged and the box was crushed', {'k': 1})
    vs.add('c', 'I was charged twice for the same order', {'k': 2})
    vs.add('c', 'Package never arrived, tracking lost', {'k': 3})
    assert vs.query('c', 'my parcel came broken and damaged', k=1)[0].metadata['k'] == 1
    assert vs.query('c', 'duplicate charge on my card', k=1)[0].metadata['k'] == 2


def test_filter_applies_before_scoring(vs):
    """RT-29: a C-2 document with the exact query text is never returned for a C-1 query."""
    vs.add('cases', 'earbuds never arrived', {'customer_id': 'C-2'})
    vs.add('cases', 'mugs arrived cracked', {'customer_id': 'C-1'})
    hits = vs.query('cases', 'earbuds never arrived', k=5, where={'customer_id': 'C-1'})
    assert [h.metadata['customer_id'] for h in hits] == ['C-1']


def test_required_scope(vs):
    vs.require_filter_on('cases', 'customer_id')
    vs.add('cases', 'x y z', {'customer_id': 'C-1'})
    with pytest.raises(ScopeRequired):
        vs.query('cases', 'x')
    with pytest.raises(ScopeRequired):
        vs.query('cases', 'x', where={'customer_id': None})
    with pytest.raises(ScopeRequired):
        vs.find('cases', {})


def test_filter_operators(vs):
    vs.add('p', 'a refund policy', {'status': 'approved', 'quarantined': False, 'customer_id': None})
    vs.add('p', 'a refund policy draft', {'status': 'pending', 'quarantined': True})
    assert vs.count('p', {'status': {'$in': ['approved', 'superseded']}}) == 1
    assert vs.count('p', {'quarantined': True}) == 1
    assert vs.count('p', {'quarantined': False}) == 1
    assert vs.count('p', {'customer_id': None}) == 2       # null and missing both match
    assert vs.count('p', {'status': {'$in': []}}) == 0


@pytest.mark.parametrize('key', ["x') OR 1=1 --", 'a.b', '$', 'customer_id]'])
def test_filter_keys_cannot_inject(vs, key):
    vs.add('p', 'text', {'a': 1})
    with pytest.raises(ValueError):
        vs.query('p', 'text', where={key: 1})


def test_update_reembeds_and_merges(vs):
    did = vs.add('c', 'blue widget', {'a': 1})
    assert vs.update('c', did, text='red gadget', metadata={'b': 2})
    h = vs.query('c', 'red gadget', k=1)[0]
    assert h.doc_id == did and h.metadata == {'a': 1, 'b': 2} and h.score > 0.9
    assert not vs.update('c', 'missing', text='x')


def test_delete_needs_filter(vs):
    vs.add('c', 'x', {'a': 1})
    with pytest.raises(ValueError):
        vs.delete('c', {})
    assert vs.delete('c', {'a': 1}) == 1


def test_persistence(tmp_path):
    path = str(tmp_path / 'v.db')
    VectorStore(path).add('c', 'persist me please', {'a': 1})
    assert VectorStore(path).query('c', 'persist me', k=1)[0].metadata == {'a': 1}


def test_embedder_is_deterministic_and_normalised():
    e = HashingEmbedder()
    a, b = e.embed('Refunds are issued'), e.embed('Refunds are issued')
    assert a == b and abs(sum(x * x for x in a) - 1.0) < 1e-9
    assert tokenize('Refunded refunds') == ['refund', 'refund']


def test_to_chunk_shape_for_access_control(vs):
    vs.add('cases', 'hello', {'customer_id': 'C-1', 'transaction_id': 'T-1'})
    c = vs.find('cases', {'customer_id': 'C-1'})[0].to_chunk()
    assert c['customer_id'] == 'C-1' and c['metadata']['transaction_id'] == 'T-1'
