from .nvd_client import NVDClient
from .opensearch_indexer import OpenSearchIndexer
from .transform import normalize_vulnerability

def _chunked(iterable, size: int):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

def ingest_all(batch_size: int = 500, **extra_params):
    client = NVDClient()
    indexer = OpenSearchIndexer()
    for raw_batch in _chunked(client.iter_all_cves(**extra_params), batch_size):
        docs = [normalize_vulnerability(v) for v in raw_batch]
        indexer.bulk_upsert(docs)
