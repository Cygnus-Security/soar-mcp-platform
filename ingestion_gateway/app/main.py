import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.checkpoint import CheckpointStore
from app.envelope import RawEventEnvelope
from app.file_reader import records
from app.kafka_io import producer
from app.settings import API_TOKEN, MAX_UPLOAD_BYTES, RAW_TOPIC, REPLAY_MAX_SLEEP_SECONDS, TENANT_ID


app = FastAPI(title="SOAR Dual-Path Ingestion Gateway", version="1.0.0")
_producer = None
_checkpoints = None


class RealtimeEventRequest(BaseModel):
    tenant_id: str = TENANT_ID
    source_product: str
    connector_id: str | None = None
    source_cursor: str | None = None
    content_type: str = "application/json"
    payload: Any


class BatchEventRequest(BaseModel):
    tenant_id: str = TENANT_ID
    source_product: str
    connector_id: str | None = None
    events: list[Any] = Field(min_length=1, max_length=1000)


def auth(authorization: str | None = Header(default=None)):
    if API_TOKEN and authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid ingestion token")


def kafka():
    global _producer
    if _producer is None:
        _producer = producer()
    return _producer


def checkpoints():
    global _checkpoints
    if _checkpoints is None:
        _checkpoints = CheckpointStore()
    return _checkpoints


def publish(envelope: RawEventEnvelope):
    kafka().send(RAW_TOPIC, key=envelope.kafka_key(), value=envelope.model_dump()).get(timeout=10)


@app.get("/health")
def health():
    return {"status": "UP", "raw_topic": RAW_TOPIC}


@app.post("/v1/events", dependencies=[Depends(auth)])
def realtime_event(request: RealtimeEventRequest):
    envelope = RawEventEnvelope(
        tenant_id=request.tenant_id,
        source_product=request.source_product,
        ingestion_mode="realtime",
        connector_id=request.connector_id,
        source_cursor=request.source_cursor,
        content_type=request.content_type,
        payload=request.payload,
    )
    publish(envelope)
    return {"accepted": 1, "ingestion_id": envelope.ingestion_id, "topic": RAW_TOPIC}


@app.post("/v1/events/batch", dependencies=[Depends(auth)])
def realtime_batch(request: BatchEventRequest):
    ids = []
    for index, event in enumerate(request.events):
        envelope = RawEventEnvelope(
            tenant_id=request.tenant_id,
            source_product=request.source_product,
            ingestion_mode="realtime",
            connector_id=request.connector_id,
            source_cursor=f"batch:{index}",
            payload=event,
        )
        publish(envelope)
        ids.append(envelope.ingestion_id)
    return {"accepted": len(ids), "ingestion_ids": ids, "topic": RAW_TOPIC}


@app.post("/v1/files", dependencies=[Depends(auth)])
async def upload_file(
        file: UploadFile = File(...),
        source_product: str = Query(...),
        tenant_id: str = Query(TENANT_ID),
        mode: str = Query("immediate", pattern="^(immediate|original|accelerated)$"),
        speed: float = Query(10.0, gt=0),
        dataset_id: str | None = Query(None),
        resume: bool = Query(True),
):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds configured size limit")
    name = file.filename or "uploaded.log"
    dataset = dataset_id or hashlib.sha256(content).hexdigest()[:16]
    checkpoint_key = f"file:{tenant_id}:{dataset}:{name}"
    start_after = int(checkpoints().get(checkpoint_key) or 0) if resume else 0
    accepted = skipped = 0
    previous_time = None
    for offset, event in records(content, name, source_product):
        if offset <= start_after:
            skipped += 1
            continue
        current_time = _event_time(event)
        if mode != "immediate" and previous_time and current_time:
            delay = max(0.0, (current_time - previous_time).total_seconds())
            if mode == "accelerated":
                delay /= speed
            await asyncio.sleep(min(delay, REPLAY_MAX_SLEEP_SECONDS))
        previous_time = current_time or previous_time
        envelope = RawEventEnvelope(
            tenant_id=tenant_id,
            source_product=source_product,
            ingestion_mode="replay",
            content_type=file.content_type or "application/octet-stream",
            source_file=name,
            source_offset=offset,
            connector_id=f"dataset:{dataset}",
            source_cursor=str(offset),
            payload=event,
        )
        publish(envelope)
        checkpoints().put(checkpoint_key, str(offset))
        accepted += 1
    kafka().flush(timeout=10)
    return {
        "dataset_id": dataset,
        "filename": name,
        "source_product": source_product,
        "mode": mode,
        "accepted": accepted,
        "skipped_by_checkpoint": skipped,
        "checkpoint": checkpoints().get(checkpoint_key),
    }


def _event_time(event: Any) -> datetime | None:
    if not isinstance(event, dict):
        return None
    value = event.get("timestamp") or event.get("@timestamp") or event.get("ts") or event.get("observed_at")
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError, OSError):
        return None
