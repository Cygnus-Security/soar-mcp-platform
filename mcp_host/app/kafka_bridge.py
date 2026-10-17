import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer


SEVERITY = {"low": 20.0, "medium": 50.0, "high": 75.0, "critical": 95.0}
SOURCE_TYPES = {
    "web": "web", "auth": "auth", "db": "application", "audit": "audit",
    "container": "container", "firewall": "firewall", "wazuh": "wazuh",
}


def bounded_int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


class KafkaBridge:
    def __init__(self):
        brokers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "redpanda:9092")
        self.normalized_topic = os.getenv("KAFKA_NORMALIZED_TOPIC", "soc.normalized.v1")
        self.raw_topic = os.getenv("KAFKA_RAW_TOPIC", "soc.raw.v1")
        self.action_topic = os.getenv("KAFKA_APPROVED_ACTION_TOPIC", "soc.action-approved.v1")
        self.result_topic = os.getenv("KAFKA_ACTION_RESULT_TOPIC", "soc.action-result.v1")
        self.tenant_id = os.getenv("SOAR_TENANT_ID", "lab")
        self.enabled = os.getenv("SOAR_KAFKA_ENABLED", "false").lower() == "true"
        self.action_batch_size = bounded_int_env("SOAR_ACTION_BATCH_SIZE", 50, 1, 100)
        self.producer = None
        self.consumer = None
        if self.enabled:
            self.producer = KafkaProducer(
                bootstrap_servers=brokers,
                key_serializer=lambda value: value.encode("utf-8"),
                value_serializer=lambda value: json.dumps(value, separators=(",", ":")).encode("utf-8"),
                acks="all",
                retries=5,
            )
            self.consumer = KafkaConsumer(
                self.action_topic,
                bootstrap_servers=brokers,
                group_id=os.getenv("SOAR_ACTION_CONSUMER_GROUP", "soar-action-executor-v1"),
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                key_deserializer=lambda value: value.decode("utf-8") if value else None,
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
                consumer_timeout_ms=50,
                max_poll_records=self.action_batch_size,
                max_poll_interval_ms=1800000,
            )

    def publish_translated_events(self, events: list[dict], source_ip: str, session_id: str):
        if not self.enabled or not self.producer:
            return 0
        published = 0
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for index, event in enumerate(events):
            source = str(event.get("source") or "application").lower()
            observed = event.get("timestamp") or now
            fingerprint = json.dumps(event, sort_keys=True, default=str)
            event_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
            normalized = {
                "schema_version": "1.0",
                "event_id": event_id,
                "tenant_id": self.tenant_id,
                "source_type": SOURCE_TYPES.get(source, "application"),
                "source_product": "soar-mcp-" + source,
                "external_id": event.get("external_id") or f"{source}-{event_id[:20]}",
                "observed_at": observed,
                "ingested_at": now,
                "event_type": event.get("action") or "unknown",
                "source_severity": event.get("rule_level"),
                "severity": SEVERITY.get(str(event.get("severity", "low")).lower(), 20.0),
                "confidence": max(0.0, min(1.0, float(event.get("confidence", 0.25)))),
                "asset_id": event.get("asset_id") or "unknown",
                "source_ip": event.get("srcip") or source_ip,
                "destination_ip": event.get("destination_ip"),
                "user_id": event.get("user_id"),
                "session_id": session_id,
                "mitre_techniques": event.get("mitre_techniques", []),
                "cve_ids": event.get("cve_ids", []),
                "evidence": [str(value)[:255] for value in event.get("evidence", [])],
                "raw_reference": f"sha256:{event_id}",
                "normalizer_version": "soar-translator-1.0.0",
                "metadata": {
                    "is_attack_signal": bool(event.get("is_attack")),
                    "intent": event.get("intent"),
                    "page": event.get("page"),
                    "sequence": index,
                },
            }
            self.producer.send(self.normalized_topic, key=f"{self.tenant_id}:{source_ip}", value=normalized)
            published += 1
        self.producer.flush(timeout=10)
        return published

    def publish_raw_events(self, events: list[dict], ingestion_mode: str = "realtime"):
        if not self.enabled or not self.producer:
            return 0
        published = 0
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for index, event in enumerate(events):
            source = str(event.get("source") or "application").lower()
            fingerprint = json.dumps(event, sort_keys=True, default=str)
            cursor = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
            envelope = {
                "schema_version": "1.0",
                "ingestion_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.tenant_id}:{source}:{cursor}")),
                "tenant_id": self.tenant_id,
                "source_product": source,
                "ingestion_mode": ingestion_mode,
                "received_at": now,
                "content_type": "application/json",
                "source_file": None,
                "source_offset": index,
                "connector_id": "mcp-collector",
                "source_cursor": cursor,
                "payload": event,
            }
            self.producer.send(self.raw_topic, key=cursor, value=envelope)
            published += 1
        self.producer.flush(timeout=10)
        return published

    def poll_approved_actions(self) -> list[dict]:
        if not self.enabled or not self.consumer:
            return []
        records = self.consumer.poll(timeout_ms=50, max_records=self.action_batch_size)
        return [record.value for batch in records.values() for record in batch]

    def commit_actions(self):
        if self.enabled and self.consumer:
            self.consumer.commit()

    def publish_action_result(self, request: dict, result: dict):
        if not self.enabled or not self.producer:
            return
        payload = {
            "schema_version": "1.0",
            "action_id": request.get("action_id", str(uuid.uuid4())),
            "incident_id": request.get("incident_id"),
            "action_type": request.get("action_type"),
            "target": request.get("target"),
            "status": result.get("status", "FAILED"),
            "message": result.get("message", "No executor message"),
            "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "details": result,
        }
        self.producer.send(self.result_topic, key=payload["action_id"], value=payload)
        self.producer.flush(timeout=10)

    def publish_automatic_results(self, source_ip: str, response: dict):
        if not self.enabled:
            return 0
        count = 0
        for action_type in response.get("executed_actions", []):
            request = {
                "action_id": str(uuid.uuid4()),
                "incident_id": response.get("incident_id"),
                "action_type": action_type,
                "target": source_ip,
            }
            result = {
                "status": response.get("status", "DRY_RUN"),
                "message": response.get("note", "SOAR automatic response"),
                "execution_mode": response.get("execution_mode", "dry-run"),
                "automatic": True,
            }
            self.publish_action_result(request, result)
            count += 1
        return count
