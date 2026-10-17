import json
from datetime import datetime, timezone


def action_log(event: str, request: dict | None = None, **fields) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "component": "soar_host",
        "event": event,
    }
    if request:
        for key in ("action_id", "incident_id", "action_type", "target"):
            value = request.get(key)
            if value not in (None, ""):
                record[key] = value
    record.update({key: value for key, value in fields.items() if value is not None})
    print(f"[SOAR_ACTION] {json.dumps(record, separators=(',', ':'), default=str)}", flush=True)
