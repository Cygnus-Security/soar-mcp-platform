import csv
import io
import json
from collections.abc import Iterator
from typing import Any


def records(content: bytes, filename: str, source_product: str) -> Iterator[tuple[int, Any]]:
    text = content.decode("utf-8", errors="replace")
    lower = filename.lower()
    if lower.endswith(".csv"):
        for index, row in enumerate(csv.DictReader(io.StringIO(text)), start=1):
            yield index, row
        return
    if lower.endswith(".json"):
        value = json.loads(text)
        for index, row in enumerate(_json_records(value), start=1):
            yield index, row
        return
    if source_product == "zeek" and "#fields" in text:
        yield from _zeek_tsv(text)
        return
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        if lower.endswith((".jsonl", ".ndjson")) or source_product in ("wazuh", "suricata", "zeek"):
            try:
                yield index, json.loads(line)
                continue
            except json.JSONDecodeError:
                pass
        yield index, {"message": line}


def _json_records(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("hits"), dict) and isinstance(value["hits"].get("hits"), list):
            return [item.get("_source", item) for item in value["hits"]["hits"]]
        for key in ("alerts", "events", "data"):
            if isinstance(value.get(key), list):
                return value[key]
        return [value]
    return [{"message": str(value)}]


def _zeek_tsv(text: str) -> Iterator[tuple[int, dict[str, str]]]:
    fields = None
    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        values = line.split("\t")
        yield index, dict(zip(fields, values))
