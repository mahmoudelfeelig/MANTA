from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass


@dataclass
class QueueItem:
    event_id: str
    payload_json: str
    attempts: int


class AdapterStorage:
    def __init__(self, sqlite_path: str) -> None:
        self._sqlite_path = sqlite_path
        self._lock = threading.Lock()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    next_attempt_epoch INTEGER NOT NULL,
                    last_error TEXT,
                    created_epoch INTEGER NOT NULL,
                    updated_epoch INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dead_letter (
                    event_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_epoch INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def enqueue_event(self, event_id: str, payload: dict) -> None:
        now = int(time.time())
        payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events(
                    event_id, event_type, payload_json, status, attempts,
                    next_attempt_epoch, last_error, created_epoch, updated_epoch
                ) VALUES (?, ?, ?, 'pending', 0, ?, NULL, ?, ?)
                """,
                (event_id, payload.get("event_type", "unknown"), payload_json, now, now, now),
            )
            conn.commit()

    def pending_events(self, now_epoch: int, limit: int) -> list[QueueItem]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, payload_json, attempts
                FROM events
                WHERE status = 'pending' AND next_attempt_epoch <= ?
                ORDER BY created_epoch ASC
                LIMIT ?
                """,
                (now_epoch, limit),
            ).fetchall()
        return [QueueItem(event_id=row[0], payload_json=row[1], attempts=row[2]) for row in rows]

    def mark_sent(self, event_id: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE events SET status='sent', updated_epoch=? WHERE event_id=?",
                (now, event_id),
            )
            conn.commit()

    def mark_retry(self, event_id: str, attempts: int, next_attempt_epoch: int, reason: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE events
                SET attempts=?, next_attempt_epoch=?, updated_epoch=?, last_error=?
                WHERE event_id=?
                """,
                (attempts, next_attempt_epoch, now, reason[:1024], event_id),
            )
            conn.commit()

    def move_to_dead_letter(self, event_id: str, payload_json: str, reason: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dead_letter(event_id, payload_json, reason, created_epoch)
                VALUES (?, ?, ?, ?)
                """,
                (event_id, payload_json, reason[:1024], now),
            )
            conn.execute("DELETE FROM events WHERE event_id=?", (event_id,))
            conn.commit()

    def stats(self) -> dict:
        with self._lock, self._connect() as conn:
            pending = conn.execute("SELECT COUNT(*) FROM events WHERE status='pending'").fetchone()[0]
            sent = conn.execute("SELECT COUNT(*) FROM events WHERE status='sent'").fetchone()[0]
            dead = conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0]
        return {"pending": pending, "sent": sent, "dead_letter": dead}

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._sqlite_path, check_same_thread=False)
