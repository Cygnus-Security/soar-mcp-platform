import os
import time

import requests

from app.checkpoint import CheckpointStore
from app.envelope import RawEventEnvelope
from app.kafka_io import producer
from app.settings import RAW_TOPIC, TENANT_ID


URL = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
USER = os.getenv("WAZUH_INDEXER_USER", "admin")
PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "true").lower() == "true"
INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL_SECONDS", "10"))
BATCH_SIZE = int(os.getenv("WAZUH_POLL_BATCH_SIZE", "200"))
CONNECTOR_ID = os.getenv("WAZUH_CONNECTOR_ID", "wazuh-indexer")


def main():
    output = producer()
    checkpoints = CheckpointStore()
    checkpoint_key = f"connector:{TENANT_ID}:{CONNECTOR_ID}"
    while True:
        cursor = checkpoints.get(checkpoint_key)
        query = {
            "size": BATCH_SIZE,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {"match_all": {}},
        }
        if cursor:
            timestamp, document_id = cursor.split("|", 1)
            query["search_after"] = [timestamp, document_id]
        try:
            response = requests.get(
                f"{URL}/wazuh-alerts-*/_search",
                auth=(USER, PASSWORD),
                json=query,
                headers={"Content-Type": "application/json"},
                verify=VERIFY_TLS,
                timeout=30,
            )
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            for hit in hits:
                source = hit.get("_source", {})
                source["_id"] = hit.get("_id")
                sort_values = hit.get("sort") or [source.get("@timestamp"), hit.get("_id")]
                envelope = RawEventEnvelope(
                    tenant_id=TENANT_ID,
                    source_product="wazuh",
                    ingestion_mode="realtime",
                    connector_id=CONNECTOR_ID,
                    source_cursor=str(hit.get("_id")),
                    payload=source,
                )
                output.send(RAW_TOPIC, key=envelope.kafka_key(), value=envelope.model_dump()).get(timeout=10)
                checkpoints.put(checkpoint_key, f"{sort_values[0]}|{sort_values[1]}")
            if hits:
                output.flush(timeout=10)
        except Exception as error:
            print(f"[WAZUH POLLER] {error}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
