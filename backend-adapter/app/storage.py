from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass


@dataclass
class QueueItem:
    event_id: str
    event_type: str
    payload_json: str
    attempts: int


@dataclass
class AlertRecord:
    alert_id: str
    device_id_pseudo: str
    app_id: str
    anomaly_score: float
    severity: str
    explanation: str
    source_model: str
    triage_status: str
    triage_note: str
    created_epoch: int
    updated_epoch: int


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
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_epoch INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    device_id_pseudo TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    source_model TEXT NOT NULL,
                    triage_status TEXT NOT NULL,
                    triage_note TEXT NOT NULL,
                    created_epoch INTEGER NOT NULL,
                    updated_epoch INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    device_id_pseudo TEXT PRIMARY KEY,
                    policy_json TEXT NOT NULL,
                    updated_epoch INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def enqueue_event(self, event_id: str, event_type: str, payload: dict) -> None:
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
                (event_id, event_type, payload_json, now, now, now),
            )
            conn.commit()

    def pending_events(self, now_epoch: int, limit: int) -> list[QueueItem]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, payload_json, attempts
                FROM events
                WHERE status = 'pending' AND next_attempt_epoch <= ?
                ORDER BY created_epoch ASC
                LIMIT ?
                """,
                (now_epoch, limit),
            ).fetchall()
        return [
            QueueItem(event_id=row[0], event_type=row[1], payload_json=row[2], attempts=row[3])
            for row in rows
        ]

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

    def move_to_dead_letter(self, event_id: str, event_type: str, payload_json: str, reason: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dead_letter(event_id, event_type, payload_json, reason, created_epoch)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, event_type, payload_json, reason[:1024], now),
            )
            conn.execute("DELETE FROM events WHERE event_id=?", (event_id,))
            conn.commit()

    def upsert_alert(self, payload: dict) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts(
                    alert_id, device_id_pseudo, app_id, anomaly_score, severity,
                    explanation, source_model, triage_status, triage_note,
                    created_epoch, updated_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,
                    COALESCE((SELECT created_epoch FROM alerts WHERE alert_id=?), ?), ?)
                """,
                (
                    payload["alert_id"],
                    payload["device_id_pseudo"],
                    payload["app_id"],
                    float(payload["anomaly_score"]),
                    payload["severity"],
                    payload.get("explanation", ""),
                    payload.get("source_model", "unknown"),
                    payload.get("triage_status", "OPEN"),
                    payload.get("triage_note", ""),
                    payload["alert_id"],
                    now,
                    now,
                ),
            )
            conn.commit()

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT alert_id, device_id_pseudo, app_id, anomaly_score, severity,
                       explanation, source_model, triage_status, triage_note,
                       created_epoch, updated_epoch
                FROM alerts WHERE alert_id=?
                """,
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return AlertRecord(*row)

    def list_alerts(self, status: str | None, limit: int) -> list[AlertRecord]:
        query = (
            """
            SELECT alert_id, device_id_pseudo, app_id, anomaly_score, severity,
                   explanation, source_model, triage_status, triage_note,
                   created_epoch, updated_epoch
            FROM alerts
            """
        )
        params: tuple = ()
        if status:
            query += " WHERE triage_status=?"
            params = (status,)
        query += " ORDER BY updated_epoch DESC LIMIT ?"
        params = params + (limit,)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [AlertRecord(*row) for row in rows]

    def update_alert_triage(self, alert_id: str, triage_status: str, triage_note: str) -> bool:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            result = conn.execute(
                """
                UPDATE alerts
                SET triage_status=?, triage_note=?, updated_epoch=?
                WHERE alert_id=?
                """,
                (triage_status, triage_note[:1024], now, alert_id),
            )
            conn.commit()
        return result.rowcount > 0

    def set_policy(self, device_id_pseudo: str, policy: dict) -> None:
        payload_json = json.dumps(policy, separators=(",", ":"), ensure_ascii=True)
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policies(device_id_pseudo, policy_json, updated_epoch)
                VALUES (?, ?, ?)
                """,
                (device_id_pseudo, payload_json, now),
            )
            conn.commit()

    def get_policy(self, device_id_pseudo: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policies WHERE device_id_pseudo=?",
                (device_id_pseudo,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def stats(self) -> dict:
        with self._lock, self._connect() as conn:
            pending = conn.execute("SELECT COUNT(*) FROM events WHERE status='pending'").fetchone()[0]
            sent = conn.execute("SELECT COUNT(*) FROM events WHERE status='sent'").fetchone()[0]
            dead = conn.execute("SELECT COUNT(*) FROM dead_letter").fetchone()[0]
            alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            policies = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
        return {
            "pending": pending,
            "sent": sent,
            "dead_letter": dead,
            "alerts": alerts,
            "policies": policies,
        }

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._sqlite_path, check_same_thread=False)
