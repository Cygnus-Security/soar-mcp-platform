import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RawEventEnvelope(BaseModel):
    schema_version: str = "1.0"
    ingestion_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    source_product: str
    ingestion_mode: str
    received_at: str = Field(default_factory=utc_now)
    content_type: str = "application/json"
    source_file: str | None = None
    source_offset: int | None = None
    connector_id: str | None = None
    source_cursor: str | None = None
    payload: Any

    def kafka_key(self) -> str:
        cursor = self.source_cursor or str(self.source_offset or "")
        identity = f"{self.tenant_id}|{self.source_product}|{self.source_file or ''}|{cursor}|{canonical(self.payload)}"
        return hashlib.sha256(identity.encode()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
