import hashlib
import ipaddress
import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from app.envelope import RawEventEnvelope, canonical, utc_now


SEVERITY_TEXT = {"informational": 10, "low": 20, "medium": 50, "high": 75, "critical": 95}
SOURCE_TYPES = {
    "wazuh": "wazuh", "suricata": "ids", "snort": "ids", "zeek": "ids",
    "firewall": "firewall", "syslog": "application", "generic_syslog": "application",
    "web": "web", "nginx": "web", "apache": "web", "auth": "auth",
    "auditd": "audit", "container": "container",
}
PATTERNS = [
    (re.compile(r"union(?:\s+all)?\s+select|\bor\s+1\s*=\s*1|information_schema", re.I), "sql_injection", 85, 0.95, "T1190"),
    (re.compile(r"\.\./|/etc/passwd|php://filter", re.I), "local_file_inclusion", 80, 0.93, "T1005"),
    (re.compile(r"<script|javascript:|onerror\s*=", re.I), "cross_site_scripting", 70, 0.90, "T1189"),
    (re.compile(r";\s*(?:whoami|id|cat|wget|curl|bash)\b|/dev/tcp/", re.I), "command_injection", 95, 0.97, "T1059"),
    (re.compile(r"failed password|authentication failure|invalid user", re.I), "authentication_failure", 45, 0.85, "T1110"),
    (re.compile(r"\b(?:drop|block|reject)\b.*\b(?:src|source|from)\b", re.I), "firewall_block", 55, 0.80, "T1046"),
]
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
COMMON_LOG = re.compile(r"^(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^]]+)]\s+\"(?P<method>\S+)\s+(?P<url>\S+)")
SNORT_PRIORITY = re.compile(r"\[Priority:\s*(\d+)]", re.I)
SNORT_MESSAGE = re.compile(r"\[\*\*]\s*\[(?:\d+:){2}\d+]\s*(.*?)\s*\[\*\*]")


def normalize(envelope: RawEventEnvelope) -> list[dict[str, Any]]:
    payloads = envelope.payload if isinstance(envelope.payload, list) else [envelope.payload]
    return [_normalize_one(envelope, payload, index) for index, payload in enumerate(payloads)]


def _normalize_one(envelope: RawEventEnvelope, payload: Any, index: int) -> dict[str, Any]:
    product = envelope.source_product.lower().replace("-", "_")
    record = payload if isinstance(payload, dict) else {"message": str(payload)}
    if product == "wazuh":
        fields = _wazuh(record)
    elif product == "suricata":
        fields = _suricata(record)
    elif product == "zeek":
        fields = _zeek(record)
    elif product == "snort":
        fields = _snort(record)
    else:
        fields = _generic(record, product)

    raw_text = fields.pop("raw_text", canonical(record))
    detection = _detect(urllib.parse.unquote_plus(raw_text))
    event_type = fields.get("event_type") or detection[0]
    severity = fields.get("severity")
    confidence = fields.get("confidence")
    evidence = list(fields.get("evidence") or [])
    techniques = list(fields.get("mitre_techniques") or [])
    if detection[0] != "activity":
        event_type = detection[0]
        severity = max(float(severity or 0), detection[1])
        confidence = max(float(confidence or 0), detection[2])
        evidence.append("pattern:" + detection[0])
        techniques.append(detection[3])

    observed_at = _timestamp(fields.get("observed_at") or record.get("timestamp") or record.get("@timestamp"))
    replay_id = f"{envelope.source_file}:{envelope.source_offset}" if envelope.source_file and envelope.source_offset is not None else None
    external_id = str(fields.get("external_id") or record.get("id") or record.get("flow_id") or envelope.source_cursor or replay_id or f"{envelope.ingestion_id}:{index}")
    identity = f"{envelope.tenant_id}|{product}|{external_id}|{observed_at}|{canonical(record)}"
    event_id = hashlib.sha256(identity.encode()).hexdigest()
    source_ip = _valid_ip(fields.get("source_ip"))
    destination_ip = _valid_ip(fields.get("destination_ip"))
    metadata = {
        "ingestion_id": envelope.ingestion_id,
        "ingestion_mode": envelope.ingestion_mode,
        "connector_id": envelope.connector_id,
        "source_file": envelope.source_file,
        "source_offset": envelope.source_offset,
        "source_rule_id": fields.get("source_rule_id"),
        "signature": fields.get("signature"),
    }
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "tenant_id": envelope.tenant_id,
        "source_type": SOURCE_TYPES.get(product, "application"),
        "source_product": product[:64],
        "external_id": external_id[:255],
        "observed_at": observed_at,
        "ingested_at": utc_now(),
        "event_type": str(event_type or "activity")[:128],
        "source_severity": fields.get("source_severity"),
        "severity": max(0.0, min(100.0, float(severity if severity is not None else 20))),
        "confidence": max(0.0, min(1.0, float(confidence if confidence is not None else 0.5))),
        "asset_id": str(fields.get("asset_id") or destination_ip or "unknown")[:128],
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user_id": _optional(fields.get("user_id"), 255),
        "session_id": _optional(fields.get("session_id") or record.get("flow_id") or source_ip, 255),
        "mitre_techniques": sorted(set(filter(None, techniques))),
        "cve_ids": sorted(set(_cves(record))),
        "evidence": list(dict.fromkeys(str(value)[:255] for value in evidence if value))[:50],
        "raw_reference": f"raw:{envelope.ingestion_id}:{envelope.source_offset if envelope.source_offset is not None else index}",
        "normalizer_version": "dual-ingestion-1.0.0",
        "metadata": {key: value for key, value in metadata.items() if value is not None},
    }


def _wazuh(record: dict) -> dict:
    rule = record.get("rule") or {}
    data = record.get("data") or {}
    agent = record.get("agent") or {}
    level = int(rule.get("level") or 0)
    techniques = rule.get("mitre", {}).get("id", []) if isinstance(rule.get("mitre"), dict) else []
    return {
        "event_type": rule.get("description") or "wazuh_alert",
        "source_severity": level,
        "severity": min(100, level * 6.25),
        "confidence": min(0.99, 0.45 + level * 0.03),
        "source_ip": data.get("srcip") or data.get("src_ip"),
        "destination_ip": data.get("dstip") or data.get("dst_ip") or agent.get("ip"),
        "asset_id": agent.get("name") or agent.get("id"),
        "user_id": data.get("srcuser") or data.get("user"),
        "source_rule_id": rule.get("id"),
        "mitre_techniques": techniques,
        "evidence": [rule.get("description")],
        "external_id": record.get("id") or record.get("_id"),
        "observed_at": record.get("timestamp") or record.get("@timestamp"),
        "raw_text": record.get("full_log") or canonical(record),
    }


def _suricata(record: dict) -> dict:
    alert = record.get("alert") or {}
    source_severity = alert.get("severity")
    severity = {1: 90, 2: 70, 3: 50, 4: 25}.get(int(source_severity or 4), 25)
    event_type = alert.get("category") or record.get("event_type") or "network_activity"
    return {
        "event_type": _slug(event_type), "source_severity": source_severity,
        "severity": severity, "confidence": 0.9 if alert else 0.55,
        "source_ip": record.get("src_ip"), "destination_ip": record.get("dest_ip"),
        "session_id": record.get("flow_id"), "signature": alert.get("signature"),
        "source_rule_id": alert.get("signature_id"), "evidence": [alert.get("signature")],
        "observed_at": record.get("timestamp"), "raw_text": canonical(record),
    }


def _zeek(record: dict) -> dict:
    return {
        "event_type": _slug(record.get("_path") or record.get("event_type") or "zeek_activity"),
        "severity": record.get("severity", 35), "confidence": record.get("confidence", 0.65),
        "source_ip": record.get("id.orig_h") or record.get("src_ip"),
        "destination_ip": record.get("id.resp_h") or record.get("dest_ip"),
        "session_id": record.get("uid"), "observed_at": record.get("ts"),
        "evidence": [record.get("note"), record.get("msg")], "raw_text": canonical(record),
    }


def _snort(record: dict) -> dict:
    message = str(record.get("message") or record.get("raw") or canonical(record))
    priority_match = SNORT_PRIORITY.search(message)
    priority = int(priority_match.group(1)) if priority_match else 3
    signature_match = SNORT_MESSAGE.search(message)
    ips = IP_PATTERN.findall(message)
    return {
        "event_type": "snort_alert", "source_severity": priority,
        "severity": {1: 90, 2: 70, 3: 50, 4: 25}.get(priority, 40), "confidence": 0.85,
        "source_ip": ips[0] if ips else None, "destination_ip": ips[1] if len(ips) > 1 else None,
        "signature": signature_match.group(1) if signature_match else None,
        "evidence": [signature_match.group(1) if signature_match else "snort_alert"],
        "raw_text": message,
    }


def _generic(record: dict, product: str) -> dict:
    message = str(record.get("message") or record.get("raw") or canonical(record))
    common = COMMON_LOG.search(message)
    ips = IP_PATTERN.findall(message)
    return {
        "event_type": record.get("event_type") or ("http_request" if common else "activity"),
        "source_severity": record.get("severity"),
        "severity": _severity(record.get("severity")), "confidence": record.get("confidence", 0.55),
        "source_ip": record.get("source_ip") or record.get("src_ip") or (common.group("src") if common else (ips[0] if ips else None)),
        "destination_ip": record.get("destination_ip") or record.get("dest_ip") or (ips[1] if len(ips) > 1 else None),
        "user_id": record.get("user_id") or record.get("user"),
        "session_id": record.get("session_id"), "external_id": record.get("external_id"),
        "observed_at": record.get("observed_at") or record.get("timestamp"),
        "evidence": record.get("evidence", []), "raw_text": message,
    }


def _detect(text: str) -> tuple[str, float, float, str | None]:
    for pattern, event_type, severity, confidence, technique in PATTERNS:
        if pattern.search(text):
            return event_type, severity, confidence, technique
    return "activity", 20, 0.5, None


def _timestamp(value: Any) -> str:
    if value is None:
        return utc_now()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat().replace("+00:00", "Z")
    text = str(value)
    try:
        numeric = float(text)
        return datetime.fromtimestamp(numeric, timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return utc_now()


def _severity(value: Any) -> float:
    if value is None:
        return 20
    if isinstance(value, (int, float)):
        return float(value)
    return SEVERITY_TEXT.get(str(value).lower(), 20)


def _valid_ip(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _cves(record: dict) -> list[str]:
    return re.findall(r"CVE-\d{4}-\d{4,}", canonical(record), re.I)


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")[:128] or "activity"


def _optional(value: Any, limit: int) -> str | None:
    return None if value in (None, "") else str(value)[:limit]
