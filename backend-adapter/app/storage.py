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
class QueueStatusRecord:
    event_id: str
    event_type: str
    attempts: int
    next_attempt_epoch: int
    last_error: str | None
    created_epoch: int
    updated_epoch: int


@dataclass
class DeadLetterRecord:
    event_id: str
    event_type: str
    reason: str
    created_epoch: int


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
    confidence: float | None
    uncertainty: float | None
    drift_score: float | None
    occurrence_count: int
    first_seen_epoch: int
    last_seen_epoch: int
    correlation_key: str
    shadow_model: str | None
    shadow_score: float | None
    suppression_reason: str | None
    data_quality_warnings_json: str
    beacon_score: float | None
    created_epoch: int
    updated_epoch: int


@dataclass
class IncidentRecord:
    correlation_key: str
    app_id: str
    alert_count: int
    max_severity_rank: int
    latest_seen_epoch: int


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
                    confidence REAL,
                    uncertainty REAL,
                    drift_score REAL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    first_seen_epoch INTEGER NOT NULL DEFAULT 0,
                    last_seen_epoch INTEGER NOT NULL DEFAULT 0,
                    correlation_key TEXT NOT NULL DEFAULT '',
                    shadow_model TEXT,
                    shadow_score REAL,
                    suppression_reason TEXT,
                    data_quality_warnings_json TEXT NOT NULL DEFAULT '[]',
                    beacon_score REAL,
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
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_device_updated
                ON alerts(device_id_pseudo, updated_epoch DESC)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_device_correlation
                ON alerts(device_id_pseudo, correlation_key, last_seen_epoch DESC)
                """
            )
            self._ensure_alert_columns(conn)
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

    def list_pending(self, limit: int) -> list[QueueStatusRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, attempts, next_attempt_epoch, last_error, created_epoch, updated_epoch
                FROM events
                WHERE status='pending'
                ORDER BY next_attempt_epoch ASC, created_epoch ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [QueueStatusRecord(*row) for row in rows]

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

    def list_dead_letter(self, limit: int) -> list[DeadLetterRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, reason, created_epoch
                FROM dead_letter
                ORDER BY created_epoch DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [DeadLetterRecord(*row) for row in rows]

    def replay_dead_letter(self, limit: int) -> int:
        now = int(time.time())
        moved = 0
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, payload_json
                FROM dead_letter
                ORDER BY created_epoch ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for event_id, event_type, payload_json in rows:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO events(
                        event_id, event_type, payload_json, status, attempts,
                        next_attempt_epoch, last_error, created_epoch, updated_epoch
                    ) VALUES (?, ?, ?, 'pending', 0, ?, NULL, ?, ?)
                    """,
                    (event_id, event_type, payload_json, now, now, now),
                )
                conn.execute("DELETE FROM dead_letter WHERE event_id=?", (event_id,))
                moved += 1
            conn.commit()
        return moved

    def upsert_alert(self, payload: dict) -> None:
        now = int(time.time())
        first_seen = int(payload.get("first_seen") or payload.get("timestamp") or now)
        last_seen = int(payload.get("last_seen") or payload.get("timestamp") or now)
        data_quality_warnings = payload.get("data_quality_warnings") or []
        if not isinstance(data_quality_warnings, list):
            data_quality_warnings = []
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts(
                    alert_id, device_id_pseudo, app_id, anomaly_score, severity,
                    explanation, source_model, triage_status, triage_note,
                    confidence, uncertainty, drift_score, occurrence_count,
                    first_seen_epoch, last_seen_epoch, correlation_key,
                    shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                    created_epoch, updated_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?,
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
                    payload.get("confidence"),
                    payload.get("uncertainty"),
                    payload.get("drift_score"),
                    int(payload.get("occurrence_count") or 1),
                    first_seen,
                    last_seen,
                    payload.get("correlation_key") or "",
                    payload.get("shadow_model"),
                    payload.get("shadow_score"),
                    payload.get("suppression_reason"),
                    json.dumps(data_quality_warnings, separators=(",", ":"), ensure_ascii=True),
                    payload.get("beacon_score"),
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
                       confidence, uncertainty, drift_score, occurrence_count,
                       first_seen_epoch, last_seen_epoch, correlation_key,
                       shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                       created_epoch, updated_epoch
                FROM alerts WHERE alert_id=?
                """,
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return AlertRecord(*row)

    def list_alerts(self, status: str | None, limit: int, device_id_pseudo: str | None = None) -> list[AlertRecord]:
        query = (
            """
            SELECT alert_id, device_id_pseudo, app_id, anomaly_score, severity,
                   explanation, source_model, triage_status, triage_note,
                   confidence, uncertainty, drift_score, occurrence_count,
                   first_seen_epoch, last_seen_epoch, correlation_key,
                   shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                   created_epoch, updated_epoch
            FROM alerts
            """
        )
        filters: list[str] = []
        params: list[object] = []
        if status:
            filters.append("triage_status=?")
            params.append(status)
        if device_id_pseudo:
            filters.append("device_id_pseudo=?")
            params.append(device_id_pseudo)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY updated_epoch DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
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

    def list_incidents(self, limit: int, device_id_pseudo: str | None = None) -> list[IncidentRecord]:
        where_clause = "WHERE correlation_key <> ''"
        params: tuple[object, ...] = (limit,)
        if device_id_pseudo:
            where_clause += " AND device_id_pseudo=?"
            params = (device_id_pseudo, limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT correlation_key,
                       MIN(app_id) AS app_id,
                       COUNT(*) AS alert_count,
                       MAX(CASE severity WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS max_severity_rank,
                       MAX(last_seen_epoch) AS latest_seen_epoch
                FROM alerts
                """
                + where_clause
                + """
                GROUP BY correlation_key
                ORDER BY latest_seen_epoch DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [IncidentRecord(*row) for row in rows]

    def quality_summary(self, device_id_pseudo: str | None = None) -> dict:
        warning_counts: dict[str, int] = {}
        query = "SELECT data_quality_warnings_json FROM alerts"
        params: tuple[object, ...] = ()
        if device_id_pseudo:
            query += " WHERE device_id_pseudo=?"
            params = (device_id_pseudo,)
        query += " ORDER BY updated_epoch DESC LIMIT 50000"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        total = 0
        for row in rows:
            total += 1
            try:
                warnings = json.loads(row[0] or "[]")
            except Exception:  # noqa: BLE001
                warnings = []
            if not isinstance(warnings, list):
                continue
            for warning in warnings:
                key = str(warning)
                warning_counts[key] = (warning_counts.get(key, 0) + 1)
        return {
            "alerts_scanned": total,
            "warning_counts": warning_counts,
        }

    def feedback_adjust_policy(
        self,
        device_id_pseudo: str,
        base_medium: float,
        base_high: float,
    ) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, int]]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT app_id,
                       SUM(CASE WHEN triage_status='FALSE_POSITIVE' THEN occurrence_count ELSE 0 END) AS fp,
                       SUM(CASE WHEN triage_status='RESOLVED' THEN occurrence_count ELSE 0 END) AS tp
                FROM alerts
                WHERE device_id_pseudo=?
                GROUP BY app_id
                """,
                (device_id_pseudo,),
            ).fetchall()

        overrides: dict[str, dict[str, float]] = {}
        stats: dict[str, dict[str, int]] = {}
        for app_id, fp_count, tp_count in rows:
            fp = int(fp_count or 0)
            tp = int(tp_count or 0)
            delta = (0.02 * fp) - (0.01 * tp)
            delta = max(-0.25, min(0.25, delta))
            medium = max(0.05, min(0.95, base_medium + delta))
            high = max(medium, min(0.99, base_high + delta))
            overrides[str(app_id)] = {"medium": float(medium), "high": float(high)}
            stats[str(app_id)] = {"false_positive": fp, "resolved": tp}
        return overrides, stats

    def simulate_policy(self, device_id_pseudo: str, policy: dict, limit: int) -> dict:
        default_thresholds = (policy.get("default_thresholds") or {}) if isinstance(policy, dict) else {}
        medium_default = float(default_thresholds.get("medium", 0.6))
        high_default = float(default_thresholds.get("high", 0.85))
        overrides = policy.get("app_threshold_overrides", {}) if isinstance(policy, dict) else {}

        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT app_id, anomaly_score
                FROM alerts
                WHERE device_id_pseudo=?
                ORDER BY updated_epoch DESC
                LIMIT ?
                """,
                (device_id_pseudo, limit),
            ).fetchall()

        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        per_app_counts: dict[str, dict[str, int]] = {}

        for app_id, score in rows:
            app_key = str(app_id)
            app_override = overrides.get(app_key, {}) if isinstance(overrides, dict) else {}
            medium = float(app_override.get("medium", medium_default))
            high = float(app_override.get("high", high_default))
            if high < medium:
                high = medium

            severity = "LOW"
            if float(score) >= high:
                severity = "HIGH"
            elif float(score) >= medium:
                severity = "MEDIUM"

            counts[severity] += 1
            per_app = per_app_counts.setdefault(app_key, {"LOW": 0, "MEDIUM": 0, "HIGH": 0})
            per_app[severity] += 1

        return {
            "rows_evaluated": len(rows),
            "severity_distribution": counts,
            "per_app_distribution": per_app_counts,
        }

    def export_retraining_samples(self, device_id_pseudo: str, limit: int) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, app_id, anomaly_score, severity, source_model, triage_status, triage_note,
                       confidence, uncertainty, drift_score, beacon_score, updated_epoch
                FROM alerts
                WHERE device_id_pseudo=? AND triage_status IN ('FALSE_POSITIVE','RESOLVED')
                ORDER BY updated_epoch DESC
                LIMIT ?
                """,
                (device_id_pseudo, limit),
            ).fetchall()

        samples = []
        for row in rows:
            (
                alert_id,
                app_id,
                anomaly_score,
                severity,
                source_model,
                triage_status,
                triage_note,
                confidence,
                uncertainty,
                drift_score,
                beacon_score,
                updated_epoch,
            ) = row
            label = 0 if triage_status == "FALSE_POSITIVE" else 1
            samples.append(
                {
                    "alert_id": alert_id,
                    "app_id": app_id,
                    "anomaly_score": float(anomaly_score),
                    "severity": severity,
                    "source_model": source_model,
                    "triage_status": triage_status,
                    "triage_note": triage_note,
                    "confidence": confidence,
                    "uncertainty": uncertainty,
                    "drift_score": drift_score,
                    "beacon_score": beacon_score,
                    "label": label,
                    "timestamp": int(updated_epoch),
                }
            )
        return samples

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

    def _ensure_alert_columns(self, conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        to_add = {
            "confidence": "ALTER TABLE alerts ADD COLUMN confidence REAL",
            "uncertainty": "ALTER TABLE alerts ADD COLUMN uncertainty REAL",
            "drift_score": "ALTER TABLE alerts ADD COLUMN drift_score REAL",
            "occurrence_count": "ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1",
            "first_seen_epoch": "ALTER TABLE alerts ADD COLUMN first_seen_epoch INTEGER NOT NULL DEFAULT 0",
            "last_seen_epoch": "ALTER TABLE alerts ADD COLUMN last_seen_epoch INTEGER NOT NULL DEFAULT 0",
            "correlation_key": "ALTER TABLE alerts ADD COLUMN correlation_key TEXT NOT NULL DEFAULT ''",
            "shadow_model": "ALTER TABLE alerts ADD COLUMN shadow_model TEXT",
            "shadow_score": "ALTER TABLE alerts ADD COLUMN shadow_score REAL",
            "suppression_reason": "ALTER TABLE alerts ADD COLUMN suppression_reason TEXT",
            "data_quality_warnings_json": "ALTER TABLE alerts ADD COLUMN data_quality_warnings_json TEXT NOT NULL DEFAULT '[]'",
            "beacon_score": "ALTER TABLE alerts ADD COLUMN beacon_score REAL",
        }
        for column, ddl in to_add.items():
            if column not in existing:
                conn.execute(ddl)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._sqlite_path, check_same_thread=False)
