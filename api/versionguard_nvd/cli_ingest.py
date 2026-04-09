from .ingest import ingest_all
from versionguard_nvd.ingest import ingest_all

if __name__ == "__main__":
    print("Starting ingestion...")
    ingest_all(batch_size=500)
    print("Ingestion completed")
