import os
import sqlite3
import threading
from datetime import datetime, timezone

from app.settings import CHECKPOINT_DB


class CheckpointStore:
    def __init__(self, path: str = CHECKPOINT_DB):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS checkpoints (checkpoint_key TEXT PRIMARY KEY, cursor_value TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )

    def get(self, key: str) -> str | None:
        with self.lock, self._connect() as connection:
            row = connection.execute(
                "SELECT cursor_value FROM checkpoints WHERE checkpoint_key = ?", (key,)
            ).fetchone()
            return row[0] if row else None

    def put(self, key: str, value: str):
        updated = datetime.now(timezone.utc).isoformat()
        with self.lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO checkpoints(checkpoint_key, cursor_value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(checkpoint_key) DO UPDATE SET cursor_value=excluded.cursor_value, updated_at=excluded.updated_at",
                (key, value, updated),
            )

    def _connect(self):
        return sqlite3.connect(self.path)
