import os


KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "redpanda:9092")
RAW_TOPIC = os.getenv("KAFKA_RAW_TOPIC", "soc.raw.v1")
NORMALIZED_TOPIC = os.getenv("KAFKA_NORMALIZED_TOPIC", "soc.normalized.v1")
DLQ_TOPIC = os.getenv("KAFKA_DLQ_TOPIC", "soc.dlq.v1")
TENANT_ID = os.getenv("SOAR_TENANT_ID", "lab")
API_TOKEN = os.getenv("INGESTION_API_TOKEN", "")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(100 * 1024 * 1024)))
CHECKPOINT_DB = os.getenv("CHECKPOINT_DB", "/app/data/checkpoints.sqlite3")
REPLAY_MAX_SLEEP_SECONDS = float(os.getenv("REPLAY_MAX_SLEEP_SECONDS", "2"))
