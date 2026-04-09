from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from api.versionguard_nvd.ingest import ingest_all

default_args = {
    "owner": "versionguard",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}

def run_ingest():
    ingest_all(batch_size=500)

with DAG(
    dag_id="versionguard_nvd_daily_ingest",
    description="Daily NVD 2.0 ingestion into OpenSearch",
    default_args=default_args,
    start_date=datetime(2024, 1, 1),
    schedule="@daily",
    catchup=False,
    max_active_runs=1,
    tags=["security", "nvd", "cve", "versionguard"],
) as dag:
    ingest_task = PythonOperator(task_id="ingest_nvd_cves", python_callable=run_ingest)
