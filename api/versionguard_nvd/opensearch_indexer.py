from opensearchpy import OpenSearch, helpers
from .config import settings

INDEX_BODY = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "sourceIdentifier": {"type": "keyword"},
            "published": {"type": "date"},
            "lastModified": {"type": "date"},
            "vulnStatus": {"type": "keyword"},
            "baseScore": {"type": "float"},
            "description_en": {"type": "text"},
            "cpeProducts": {"type": "keyword"},
            "cpeVendors": {"type": "keyword"},
            "cpeTargets": {"type": "object", "enabled": True},
            "configurations": {"type": "object", "enabled": True},
            "nvdUrl": {"type": "keyword"},
        }
    },
}

class OpenSearchIndexer:
    def __init__(self) -> None:
        self.client = OpenSearch(settings.open_search_url)
        self.index_name = settings.open_search_index
    def ensure_index(self) -> None:
        if not self.client.indices.exists(index=self.index_name):
            self.client.indices.create(index=self.index_name, body=INDEX_BODY)
    def bulk_upsert(self, docs):
        if not docs:
            return
        self.ensure_index()
        actions = [{"_op_type": "index", "_index": self.index_name, "_id": doc["id"], "_source": doc} for doc in docs]
        helpers.bulk(self.client, actions)
