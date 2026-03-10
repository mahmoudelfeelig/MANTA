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
class EventRecord:
    event_id: str
    event_type: str
    status: str
    attempts: int
    payload_json: str
    last_error: str | None
    created_epoch: int
    updated_epoch: int


@dataclass
class AlertRecord:
    alert_id: str
    device_id_pseudo: str
    app_id: str
    anomaly_score: float
    base_anomaly_score: float | None
    context_score: float | None
    response_score: float | None
    severity: str
    explanation: str
    source_model: str
    top_features_json: str
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
    feature_window_json: str
    site_hint: str | None
    created_epoch: int
    updated_epoch: int


@dataclass
class IncidentRecord:
    correlation_key: str
    device_id_pseudo: str
    app_id: str
    alert_count: int
    max_severity_rank: int
    latest_seen_epoch: int


@dataclass
class RemoteModelRecord:
    device_id_pseudo: str
    model_json: str
    updated_epoch: int


@dataclass
class RemoteModelVersionRecord:
    device_id_pseudo: str
    version: int
    model_json: str
    training_job_id: str | None
    created_epoch: int
    activated_epoch: int | None
    is_active: int


@dataclass
class RemoteModelJobRecord:
    job_id: str
    device_id_pseudo: str
    status: str
    created_epoch: int
    started_epoch: int | None
    completed_epoch: int | None
    error: str | None
    sample_count: int | None
    output_version: int | None


@dataclass
class DeviceRecord:
    device_id_pseudo: str
    observed_name: str | None
    display_name: str | None
    metadata_updated_epoch: int
    last_seen_epoch: int
    last_flow_epoch: int
    last_alert_epoch: int
    last_heartbeat_epoch: int
    last_policy_epoch: int
    total_events: int


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
                    base_anomaly_score REAL,
                    context_score REAL,
                    response_score REAL,
                    severity TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    source_model TEXT NOT NULL,
                    top_features_json TEXT NOT NULL DEFAULT '[]',
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
                    feature_window_json TEXT NOT NULL DEFAULT '{}',
                    site_hint TEXT,
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
                CREATE TABLE IF NOT EXISTS remote_models (
                    device_id_pseudo TEXT PRIMARY KEY,
                    model_json TEXT NOT NULL,
                    updated_epoch INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remote_model_registry (
                    device_id_pseudo TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    model_json TEXT NOT NULL,
                    training_job_id TEXT,
                    created_epoch INTEGER NOT NULL,
                    activated_epoch INTEGER,
                    is_active INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (device_id_pseudo, version)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remote_model_jobs (
                    job_id TEXT PRIMARY KEY,
                    device_id_pseudo TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_epoch INTEGER NOT NULL,
                    started_epoch INTEGER,
                    completed_epoch INTEGER,
                    error TEXT,
                    sample_count INTEGER,
                    output_version INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id_pseudo TEXT PRIMARY KEY,
                    last_seen_epoch INTEGER NOT NULL DEFAULT 0,
                    last_flow_epoch INTEGER NOT NULL DEFAULT 0,
                    last_alert_epoch INTEGER NOT NULL DEFAULT 0,
                    last_heartbeat_epoch INTEGER NOT NULL DEFAULT 0,
                    last_policy_epoch INTEGER NOT NULL DEFAULT 0,
                    total_events INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_metadata (
                    device_id_pseudo TEXT PRIMARY KEY,
                    observed_name TEXT,
                    display_name TEXT,
                    updated_epoch INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            # Run column migrations before creating indexes that depend on new columns.
            self._ensure_alert_columns(conn)
            self._ensure_device_columns(conn)
            self._migrate_legacy_remote_models(conn)
            self._rebuild_device_index(conn)
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
            conn.commit()

    def enqueue_event(self, event_id: str, event_type: str, payload: dict) -> None:
        now = int(time.time())
        payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        device_id = str(payload.get("device_id_pseudo") or "").strip()
        device_label = str(payload.get("device_label") or "").strip() or None
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
            if device_id:
                self._upsert_device_activity(conn, device_id_pseudo=device_id, event_type=event_type, epoch=now)
                if device_label:
                    self._upsert_device_metadata(
                        conn,
                        device_id_pseudo=device_id,
                        observed_name=device_label,
                        epoch=now,
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

    def list_events(
        self,
        status: str | None,
        limit: int,
        event_type: str | None = None,
        device_id_pseudo: str | None = None,
        device_ids: list[str] | None = None,
    ) -> list[EventRecord]:
        query = (
            """
            SELECT event_id, event_type, status, attempts, payload_json, last_error, created_epoch, updated_epoch
            FROM events
            """
        )
        filters: list[str] = []
        params: list[object] = []
        if status:
            filters.append("status=?")
            params.append(status)
        if event_type:
            filters.append("event_type=?")
            params.append(event_type)
        target_device_ids = [device_id for device_id in (device_ids or []) if device_id]
        if device_id_pseudo and device_id_pseudo not in target_device_ids:
            target_device_ids.append(device_id_pseudo)
        if target_device_ids:
            clauses = []
            for target_device_id in target_device_ids:
                clauses.append("payload_json LIKE ?")
                params.append(f'%\"device_id_pseudo\":\"{target_device_id}\"%')
            filters.append("(" + " OR ".join(clauses) + ")")
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY updated_epoch DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [EventRecord(*row) for row in rows]

    def list_devices(self, limit: int) -> list[DeviceRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT d.device_id_pseudo,
                       m.observed_name,
                       m.display_name,
                       COALESCE(m.updated_epoch, 0),
                       d.last_seen_epoch,
                       d.last_flow_epoch,
                       d.last_alert_epoch,
                       d.last_heartbeat_epoch,
                       d.last_policy_epoch,
                       d.total_events
                FROM devices d
                LEFT JOIN device_metadata m ON m.device_id_pseudo = d.device_id_pseudo
                ORDER BY
                    MAX(d.last_flow_epoch, d.last_alert_epoch, d.last_heartbeat_epoch) DESC,
                    d.last_policy_epoch DESC,
                    d.last_seen_epoch DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [DeviceRecord(*row) for row in rows]

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
        device_label = str(payload.get("device_label") or "").strip() or None
        anomaly_score = float(payload["anomaly_score"])
        base_anomaly_score = payload.get("base_anomaly_score")
        if base_anomaly_score is None:
            base_anomaly_score = anomaly_score
        context_score = payload.get("context_score")
        if context_score is None:
            context_score = 0.0
        response_score = payload.get("response_score")
        if response_score is None:
            response_score = anomaly_score
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts(
                    alert_id, device_id_pseudo, app_id, anomaly_score, base_anomaly_score, context_score, response_score, severity,
                    explanation, source_model, top_features_json, triage_status, triage_note,
                    confidence, uncertainty, drift_score, occurrence_count,
                    first_seen_epoch, last_seen_epoch, correlation_key,
                    shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                    feature_window_json, site_hint,
                    created_epoch, updated_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    COALESCE((SELECT created_epoch FROM alerts WHERE alert_id=?), ?), ?)
                """,
                (
                    payload["alert_id"],
                    payload["device_id_pseudo"],
                    payload["app_id"],
                    anomaly_score,
                    base_anomaly_score,
                    context_score,
                    response_score,
                    payload["severity"],
                    payload.get("explanation", ""),
                    payload.get("source_model", "unknown"),
                    json.dumps(payload.get("top_features") or [], separators=(",", ":"), ensure_ascii=True),
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
                    json.dumps(payload.get("window_features") or {}, separators=(",", ":"), ensure_ascii=True),
                    payload.get("site_hint"),
                    payload["alert_id"],
                    now,
                    now,
                ),
            )
            device_id = str(payload.get("device_id_pseudo") or "").strip()
            if device_id:
                self._upsert_device_activity(conn, device_id_pseudo=device_id, event_type="mobile_alert", epoch=now)
                if device_label:
                    self._upsert_device_metadata(
                        conn,
                        device_id_pseudo=device_id,
                        observed_name=device_label,
                        epoch=now,
                    )
            conn.commit()

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT alert_id, device_id_pseudo, app_id, anomaly_score, base_anomaly_score, context_score, response_score, severity,
                       explanation, source_model, top_features_json, triage_status, triage_note,
                       confidence, uncertainty, drift_score, occurrence_count,
                       first_seen_epoch, last_seen_epoch, correlation_key,
                       shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                       feature_window_json, site_hint,
                       created_epoch, updated_epoch
                FROM alerts WHERE alert_id=?
                """,
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return AlertRecord(*row)

    def list_alerts(
        self,
        status: str | None,
        limit: int,
        device_id_pseudo: str | None = None,
        device_ids: list[str] | None = None,
        severity: str | None = None,
        source_model: str | None = None,
        search: str | None = None,
    ) -> list[AlertRecord]:
        query = (
            """
            SELECT alert_id, device_id_pseudo, app_id, anomaly_score, base_anomaly_score, context_score, response_score, severity,
                   explanation, source_model, top_features_json, triage_status, triage_note,
                   confidence, uncertainty, drift_score, occurrence_count,
                   first_seen_epoch, last_seen_epoch, correlation_key,
                   shadow_model, shadow_score, suppression_reason, data_quality_warnings_json, beacon_score,
                   feature_window_json, site_hint,
                   created_epoch, updated_epoch
            FROM alerts
            """
        )
        filters: list[str] = []
        params: list[object] = []
        if status:
            filters.append("triage_status=?")
            params.append(status)
        target_device_ids = [device_id for device_id in (device_ids or []) if device_id]
        if device_id_pseudo and device_id_pseudo not in target_device_ids:
            target_device_ids.append(device_id_pseudo)
        if target_device_ids:
            placeholders = ",".join("?" for _ in target_device_ids)
            filters.append(f"device_id_pseudo IN ({placeholders})")
            params.extend(target_device_ids)
        if severity:
            filters.append("severity=?")
            params.append(severity)
        if source_model:
            filters.append("source_model=?")
            params.append(source_model)
        if search:
            filters.append("(app_id LIKE ? OR explanation LIKE ? OR top_features_json LIKE ? OR site_hint LIKE ? OR device_id_pseudo LIKE ?)")
            needle = f"%{search}%"
            params.extend([needle, needle, needle, needle, needle])
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

    def list_incidents(
        self,
        limit: int,
        device_id_pseudo: str | None = None,
        device_ids: list[str] | None = None,
    ) -> list[IncidentRecord]:
        where_clause = "WHERE correlation_key <> ''"
        params: list[object] = []
        target_device_ids = [device_id for device_id in (device_ids or []) if device_id]
        if device_id_pseudo and device_id_pseudo not in target_device_ids:
            target_device_ids.append(device_id_pseudo)
        if target_device_ids:
            placeholders = ",".join("?" for _ in target_device_ids)
            where_clause += f" AND device_id_pseudo IN ({placeholders})"
            params.extend(target_device_ids)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT correlation_key,
                       MIN(device_id_pseudo) AS device_id_pseudo,
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
                tuple(params + [limit]),
            ).fetchall()
        return [IncidentRecord(*row) for row in rows]

    def quality_summary(
        self,
        device_id_pseudo: str | None = None,
        device_ids: list[str] | None = None,
    ) -> dict:
        warning_counts: dict[str, int] = {}
        query = "SELECT data_quality_warnings_json FROM alerts"
        params: list[object] = []
        target_device_ids = [device_id for device_id in (device_ids or []) if device_id]
        if device_id_pseudo and device_id_pseudo not in target_device_ids:
            target_device_ids.append(device_id_pseudo)
        if target_device_ids:
            placeholders = ",".join("?" for _ in target_device_ids)
            query += f" WHERE device_id_pseudo IN ({placeholders})"
            params.extend(target_device_ids)
        query += " ORDER BY updated_epoch DESC LIMIT 50000"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
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
                SELECT alert_id, app_id, anomaly_score, base_anomaly_score, context_score, response_score, severity, source_model, triage_status, triage_note,
                       top_features_json, confidence, uncertainty, drift_score, beacon_score, feature_window_json,
                       site_hint, updated_epoch
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
                base_anomaly_score,
                context_score,
                response_score,
                severity,
                source_model,
                triage_status,
                triage_note,
                top_features_json,
                confidence,
                uncertainty,
                drift_score,
                beacon_score,
                feature_window_json,
                site_hint,
                updated_epoch,
            ) = row
            label = 0 if triage_status == "FALSE_POSITIVE" else 1
            samples.append(
                {
                    "alert_id": alert_id,
                    "app_id": app_id,
                    "anomaly_score": float(anomaly_score),
                    "base_anomaly_score": None if base_anomaly_score is None else float(base_anomaly_score),
                    "context_score": None if context_score is None else float(context_score),
                    "response_score": None if response_score is None else float(response_score),
                    "severity": severity,
                    "source_model": source_model,
                    "triage_status": triage_status,
                    "triage_note": triage_note,
                    "top_features": json.loads(top_features_json or "[]"),
                    "confidence": confidence,
                    "uncertainty": uncertainty,
                    "drift_score": drift_score,
                    "beacon_score": beacon_score,
                    "window_features": json.loads(feature_window_json or "{}"),
                    "site_hint": site_hint,
                    "label": label,
                    "timestamp": int(updated_epoch),
                }
            )
        return samples

    def remote_feedback_adjustment(self, app_id: str) -> dict[str, float]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN triage_status='FALSE_POSITIVE' THEN occurrence_count ELSE 0 END) AS fp,
                    SUM(CASE WHEN triage_status='RESOLVED' THEN occurrence_count ELSE 0 END) AS tp
                FROM alerts
                WHERE app_id=?
                """,
                (app_id,),
            ).fetchone()

        fp = float((row[0] or 0) if row else 0)
        tp = float((row[1] or 0) if row else 0)
        total = max(1.0, fp + tp)
        bias = max(-0.18, min(0.18, ((tp - fp) / total) * 0.18))
        confidence_boost = max(0.0, min(0.12, (tp / total) * 0.12))
        return {
            "score_bias": bias,
            "confidence_boost": confidence_boost,
            "false_positive": fp,
            "resolved": tp,
        }

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
            self._upsert_device_policy_activity(conn, device_id_pseudo=device_id_pseudo, epoch=now)
            conn.commit()

    def note_device_seen(self, device_id_pseudo: str, source: str = "event") -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            current = conn.execute(
                """
                SELECT last_seen_epoch, last_flow_epoch, last_alert_epoch, last_heartbeat_epoch, last_policy_epoch, total_events
                FROM devices
                WHERE device_id_pseudo=?
                """,
                (device_id_pseudo,),
            ).fetchone()
            if current is None:
                initial_seen = 0 if source == "policy" else now
                initial_heartbeat = now if source == "heartbeat" else 0
                initial_policy = now if source == "policy" else 0
                conn.execute(
                    """
                    INSERT INTO devices(
                        device_id_pseudo,
                        last_seen_epoch,
                        last_flow_epoch,
                        last_alert_epoch,
                        last_heartbeat_epoch,
                        last_policy_epoch,
                        total_events
                    )
                    VALUES (?, ?, 0, 0, ?, ?, 0)
                    """,
                    (device_id_pseudo, initial_seen, initial_heartbeat, initial_policy),
                )
                conn.commit()
                return

            last_seen, last_flow, last_alert, last_heartbeat, last_policy, total_events = current
            conn.execute(
                """
                UPDATE devices
                SET last_seen_epoch=?,
                    last_flow_epoch=?,
                    last_alert_epoch=?,
                    last_heartbeat_epoch=?,
                    last_policy_epoch=?,
                    total_events=?
                WHERE device_id_pseudo=?
                """,
                (
                    max(int(last_seen or 0), now if source != "policy" else int(last_seen or 0)),
                    int(last_flow or 0),
                    int(last_alert or 0),
                    max(int(last_heartbeat or 0), now if source == "heartbeat" else int(last_heartbeat or 0)),
                    max(int(last_policy or 0), now if source == "policy" else int(last_policy or 0)),
                    int(total_events or 0),
                    device_id_pseudo,
                ),
            )
            conn.commit()

    def note_device_heartbeat(self, device_id_pseudo: str, observed_name: str | None = None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            self._upsert_device_heartbeat(conn, device_id_pseudo=device_id_pseudo, epoch=now)
            if observed_name:
                self._upsert_device_metadata(
                    conn,
                    device_id_pseudo=device_id_pseudo,
                    observed_name=observed_name,
                    epoch=now,
                )
            conn.commit()

    def get_remote_model(self, device_id_pseudo: str) -> dict | None:
        with self._lock, self._connect() as conn:
            for target_device_id in (device_id_pseudo, "__global__"):
                row = conn.execute(
                    """
                    SELECT model_json
                    FROM remote_model_registry
                    WHERE device_id_pseudo=? AND is_active=1
                    ORDER BY version DESC
                    LIMIT 1
                    """,
                    (target_device_id,),
                ).fetchone()
                if row is not None:
                    return json.loads(row[0])
                row = conn.execute(
                    "SELECT model_json FROM remote_models WHERE device_id_pseudo=?",
                    (target_device_id,),
                ).fetchone()
                if row is not None:
                    return json.loads(row[0])
        if row is None:
            return None
        return json.loads(row[0])

    def set_remote_model(
        self,
        device_id_pseudo: str,
        model: dict,
        activate: bool = True,
        training_job_id: str | None = None,
    ) -> dict:
        payload_json = json.dumps(model, separators=(",", ":"), ensure_ascii=True)
        now = int(time.time())
        with self._lock, self._connect() as conn:
            next_version = (
                conn.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM remote_model_registry WHERE device_id_pseudo=?",
                    (device_id_pseudo,),
                ).fetchone()[0]
            )
            stored = dict(model)
            stored.setdefault("model_family", str(stored.get("model_type") or "unknown"))
            stored["version"] = int(next_version)
            payload_json = json.dumps(stored, separators=(",", ":"), ensure_ascii=True)
            if activate:
                conn.execute(
                    "UPDATE remote_model_registry SET is_active=0 WHERE device_id_pseudo=?",
                    (device_id_pseudo,),
                )
            conn.execute(
                """
                INSERT OR REPLACE INTO remote_model_registry(
                    device_id_pseudo, version, model_json, training_job_id, created_epoch, activated_epoch, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id_pseudo,
                    next_version,
                    payload_json,
                    training_job_id,
                    now,
                    now if activate else None,
                    1 if activate else 0,
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO remote_models(device_id_pseudo, model_json, updated_epoch)
                VALUES (?, ?, ?)
                """,
                (device_id_pseudo, payload_json, now if activate else now),
            )
            conn.commit()
        return stored

    def list_remote_model_versions(self, device_id_pseudo: str, limit: int) -> list[RemoteModelVersionRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT device_id_pseudo, version, model_json, training_job_id, created_epoch, activated_epoch, is_active
                FROM remote_model_registry
                WHERE device_id_pseudo=?
                ORDER BY version DESC
                LIMIT ?
                """,
                (device_id_pseudo, limit),
            ).fetchall()
        return [RemoteModelVersionRecord(*row) for row in rows]

    def activate_remote_model_version(self, device_id_pseudo: str, version: int) -> dict | None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT model_json
                FROM remote_model_registry
                WHERE device_id_pseudo=? AND version=?
                """,
                (device_id_pseudo, version),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE remote_model_registry SET is_active=0 WHERE device_id_pseudo=?",
                (device_id_pseudo,),
            )
            conn.execute(
                """
                UPDATE remote_model_registry
                SET is_active=1, activated_epoch=?
                WHERE device_id_pseudo=? AND version=?
                """,
                (now, device_id_pseudo, version),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO remote_models(device_id_pseudo, model_json, updated_epoch)
                VALUES (?, ?, ?)
                """,
                (device_id_pseudo, row[0], now),
            )
            conn.commit()
        return json.loads(row[0])

    def create_remote_model_job(self, job_id: str, device_id_pseudo: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO remote_model_jobs(
                    job_id, device_id_pseudo, status, created_epoch, started_epoch, completed_epoch, error, sample_count, output_version
                ) VALUES (?, ?, 'queued', ?, NULL, NULL, NULL, NULL, NULL)
                """,
                (job_id, device_id_pseudo, now),
            )
            conn.commit()

    def mark_remote_model_job_running(self, job_id: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE remote_model_jobs SET status='running', started_epoch=?, error=NULL WHERE job_id=?",
                (now, job_id),
            )
            conn.commit()

    def mark_remote_model_job_completed(self, job_id: str, sample_count: int, output_version: int) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE remote_model_jobs
                SET status='completed', completed_epoch=?, sample_count=?, output_version=?, error=NULL
                WHERE job_id=?
                """,
                (now, sample_count, output_version, job_id),
            )
            conn.commit()

    def mark_remote_model_job_failed(self, job_id: str, error: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE remote_model_jobs
                SET status='failed', completed_epoch=?, error=?
                WHERE job_id=?
                """,
                (now, error[:1024], job_id),
            )
            conn.commit()

    def list_remote_model_jobs(self, device_id_pseudo: str, limit: int) -> list[RemoteModelJobRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT job_id, device_id_pseudo, status, created_epoch, started_epoch, completed_epoch, error, sample_count, output_version
                FROM remote_model_jobs
                WHERE device_id_pseudo=?
                ORDER BY created_epoch DESC
                LIMIT ?
                """,
                (device_id_pseudo, limit),
            ).fetchall()
        return [RemoteModelJobRecord(*row) for row in rows]

    def get_policy(self, device_id_pseudo: str) -> dict | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policies WHERE device_id_pseudo=?",
                (device_id_pseudo,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set_device_display_name(self, device_id_pseudo: str, display_name: str | None) -> dict | None:
        now = int(time.time())
        normalized = (display_name or "").strip() or None
        with self._lock, self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM devices WHERE device_id_pseudo=?",
                (device_id_pseudo,),
            ).fetchone()
            if exists is None:
                return None
            current = conn.execute(
                """
                SELECT observed_name, display_name, updated_epoch
                FROM device_metadata
                WHERE device_id_pseudo=?
                """,
                (device_id_pseudo,),
            ).fetchone()
            if current is None:
                conn.execute(
                    """
                    INSERT INTO device_metadata(device_id_pseudo, observed_name, display_name, updated_epoch)
                    VALUES (?, NULL, ?, ?)
                    """,
                    (device_id_pseudo, normalized, now),
                )
            else:
                conn.execute(
                    """
                    UPDATE device_metadata
                    SET display_name=?, updated_epoch=?
                    WHERE device_id_pseudo=?
                    """,
                    (normalized, max(int(current[2] or 0), now), device_id_pseudo),
                )
            conn.commit()
            row = conn.execute(
                """
                SELECT observed_name, display_name, updated_epoch
                FROM device_metadata
                WHERE device_id_pseudo=?
                """,
                (device_id_pseudo,),
            ).fetchone()
        if row is None:
            return None
        return {
            "device_id_pseudo": device_id_pseudo,
            "observed_name": row[0],
            "display_name": row[1],
            "metadata_updated_epoch": row[2],
        }

    def refresh_device_index(self) -> None:
        with self._lock, self._connect() as conn:
            self._rebuild_device_index(conn)
            conn.commit()

    def purge_data(
        self,
        device_ids: list[str],
        *,
        clear_events: bool,
        clear_alerts: bool,
        clear_policies: bool,
        clear_models: bool,
        clear_dead_letter: bool,
        purge_test_data: bool,
        all_devices: bool,
    ) -> dict[str, int]:
        patterns = ["%\"device_id_pseudo\":\"abcd1234\"%", "%\"device_id_pseudo\":\"device-test-%", "%com.test%", "%manual%", "%test%"]
        counters = {
            "events": 0,
            "alerts": 0,
            "policies": 0,
            "models": 0,
            "dead_letter": 0,
            "devices": 0,
        }
        with self._lock, self._connect() as conn:
            targets = [device_id for device_id in device_ids if device_id and device_id != "__global__"]

            if clear_events:
                if all_devices:
                    counters["events"] += conn.execute("DELETE FROM events").rowcount
                else:
                    for device_id in targets:
                        counters["events"] += conn.execute(
                            "DELETE FROM events WHERE payload_json LIKE ?",
                            (f'%\"device_id_pseudo\":\"{device_id}\"%',),
                        ).rowcount
            if clear_dead_letter:
                if all_devices:
                    counters["dead_letter"] += conn.execute("DELETE FROM dead_letter").rowcount
                else:
                    for device_id in targets:
                        counters["dead_letter"] += conn.execute(
                            "DELETE FROM dead_letter WHERE payload_json LIKE ?",
                            (f'%\"device_id_pseudo\":\"{device_id}\"%',),
                        ).rowcount
            if clear_alerts:
                if all_devices:
                    counters["alerts"] += conn.execute("DELETE FROM alerts").rowcount
                else:
                    for device_id in targets:
                        counters["alerts"] += conn.execute(
                            "DELETE FROM alerts WHERE device_id_pseudo=?",
                            (device_id,),
                        ).rowcount
            if clear_policies:
                if all_devices:
                    counters["policies"] += conn.execute("DELETE FROM policies WHERE device_id_pseudo <> '__global__'").rowcount
                else:
                    for device_id in targets:
                        counters["policies"] += conn.execute(
                            "DELETE FROM policies WHERE device_id_pseudo=?",
                            (device_id,),
                        ).rowcount
            if clear_models:
                if all_devices:
                    counters["models"] += conn.execute("DELETE FROM remote_models").rowcount
                    counters["models"] += conn.execute("DELETE FROM remote_model_registry").rowcount
                    counters["models"] += conn.execute("DELETE FROM remote_model_jobs").rowcount
                else:
                    for device_id in targets:
                        counters["models"] += conn.execute(
                            "DELETE FROM remote_models WHERE device_id_pseudo=?",
                            (device_id,),
                        ).rowcount
                        counters["models"] += conn.execute(
                            "DELETE FROM remote_model_registry WHERE device_id_pseudo=?",
                            (device_id,),
                        ).rowcount
                        counters["models"] += conn.execute(
                            "DELETE FROM remote_model_jobs WHERE device_id_pseudo=?",
                            (device_id,),
                        ).rowcount
            if all_devices and (clear_events or clear_alerts or clear_policies or clear_models):
                counters["devices"] += conn.execute("DELETE FROM device_metadata").rowcount
            elif targets and (clear_events or clear_alerts or clear_policies or clear_models):
                placeholders = ",".join("?" for _ in targets)
                counters["devices"] += conn.execute(
                    f"DELETE FROM device_metadata WHERE device_id_pseudo IN ({placeholders})",
                    tuple(targets),
                ).rowcount
            if all_devices and (clear_events or clear_alerts or clear_policies or clear_models):
                conn.execute("DELETE FROM devices")
            elif targets and (clear_events or clear_alerts or clear_policies or clear_models):
                placeholders = ",".join("?" for _ in targets)
                conn.execute(
                    f"DELETE FROM devices WHERE device_id_pseudo IN ({placeholders})",
                    tuple(targets),
                )

            if purge_test_data:
                for pattern in patterns:
                    counters["events"] += conn.execute("DELETE FROM events WHERE payload_json LIKE ?", (pattern,)).rowcount
                    counters["dead_letter"] += conn.execute("DELETE FROM dead_letter WHERE payload_json LIKE ?", (pattern,)).rowcount
                counters["alerts"] += conn.execute(
                    """
                    DELETE FROM alerts
                    WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')
                       OR app_id='com.test'
                       OR alert_id LIKE 'test-%'
                       OR alert_id LIKE '%manual%'
                    """
                ).rowcount
                counters["policies"] += conn.execute(
                    "DELETE FROM policies WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')"
                ).rowcount
                counters["models"] += conn.execute(
                    "DELETE FROM remote_models WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')"
                ).rowcount
                counters["models"] += conn.execute(
                    "DELETE FROM remote_model_registry WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')"
                ).rowcount
                counters["models"] += conn.execute(
                    "DELETE FROM remote_model_jobs WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')"
                ).rowcount
                counters["devices"] += conn.execute(
                    "DELETE FROM device_metadata WHERE device_id_pseudo IN ('abcd1234', 'device-test-1234')"
                ).rowcount

            self._rebuild_device_index(conn)
            counters["devices"] = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            conn.commit()
        return counters

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
            "base_anomaly_score": "ALTER TABLE alerts ADD COLUMN base_anomaly_score REAL",
            "context_score": "ALTER TABLE alerts ADD COLUMN context_score REAL",
            "response_score": "ALTER TABLE alerts ADD COLUMN response_score REAL",
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
            "top_features_json": "ALTER TABLE alerts ADD COLUMN top_features_json TEXT NOT NULL DEFAULT '[]'",
            "feature_window_json": "ALTER TABLE alerts ADD COLUMN feature_window_json TEXT NOT NULL DEFAULT '{}'",
            "site_hint": "ALTER TABLE alerts ADD COLUMN site_hint TEXT",
        }
        for column, ddl in to_add.items():
            if column not in existing:
                conn.execute(ddl)

    def _ensure_device_columns(self, conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "last_heartbeat_epoch" not in existing:
            conn.execute("ALTER TABLE devices ADD COLUMN last_heartbeat_epoch INTEGER NOT NULL DEFAULT 0")

    def _upsert_device_activity(
        self,
        conn: sqlite3.Connection,
        device_id_pseudo: str,
        event_type: str,
        epoch: int,
    ) -> None:
        current = conn.execute(
            """
            SELECT last_seen_epoch, last_flow_epoch, last_alert_epoch, last_heartbeat_epoch, last_policy_epoch, total_events
            FROM devices
            WHERE device_id_pseudo=?
            """,
            (device_id_pseudo,),
        ).fetchone()
        if current is None:
            last_flow = epoch if event_type == "mobile_flow" else 0
            last_alert = epoch if event_type == "mobile_alert" else 0
            conn.execute(
                """
                INSERT INTO devices(
                    device_id_pseudo,
                    last_seen_epoch,
                    last_flow_epoch,
                    last_alert_epoch,
                    last_heartbeat_epoch,
                    last_policy_epoch,
                    total_events
                )
                VALUES (?, ?, ?, ?, 0, 0, 1)
                """,
                (device_id_pseudo, epoch, last_flow, last_alert),
            )
            return

        last_seen, last_flow, last_alert, last_heartbeat, last_policy, total_events = current
        conn.execute(
            """
            UPDATE devices
            SET last_seen_epoch=?,
                last_flow_epoch=?,
                last_alert_epoch=?,
                last_heartbeat_epoch=?,
                last_policy_epoch=?,
                total_events=?
            WHERE device_id_pseudo=?
            """,
            (
                max(int(last_seen or 0), epoch),
                max(int(last_flow or 0), epoch if event_type == "mobile_flow" else int(last_flow or 0)),
                max(int(last_alert or 0), epoch if event_type == "mobile_alert" else int(last_alert or 0)),
                int(last_heartbeat or 0),
                int(last_policy or 0),
                int(total_events or 0) + 1,
                device_id_pseudo,
            ),
        )

    def _upsert_device_policy_activity(
        self,
        conn: sqlite3.Connection,
        device_id_pseudo: str,
        epoch: int,
    ) -> None:
        current = conn.execute(
            """
            SELECT last_seen_epoch, last_flow_epoch, last_alert_epoch, last_heartbeat_epoch, last_policy_epoch, total_events
            FROM devices
            WHERE device_id_pseudo=?
            """,
            (device_id_pseudo,),
        ).fetchone()
        if current is None:
            conn.execute(
                """
                INSERT INTO devices(device_id_pseudo, last_seen_epoch, last_flow_epoch, last_alert_epoch, last_heartbeat_epoch, last_policy_epoch, total_events)
                VALUES (?, 0, 0, 0, 0, ?, 0)
                """,
                (device_id_pseudo, epoch),
            )
            return

        last_seen, last_flow, last_alert, last_heartbeat, _last_policy, total_events = current
        conn.execute(
            """
            UPDATE devices
            SET last_seen_epoch=?,
                last_flow_epoch=?,
                last_alert_epoch=?,
                last_heartbeat_epoch=?,
                last_policy_epoch=?,
                total_events=?
            WHERE device_id_pseudo=?
            """,
            (
                int(last_seen or 0),
                int(last_flow or 0),
                int(last_alert or 0),
                int(last_heartbeat or 0),
                epoch,
                int(total_events or 0),
                device_id_pseudo,
            ),
        )

    def _upsert_device_heartbeat(
        self,
        conn: sqlite3.Connection,
        device_id_pseudo: str,
        epoch: int,
    ) -> None:
        current = conn.execute(
            """
            SELECT last_seen_epoch, last_flow_epoch, last_alert_epoch, last_heartbeat_epoch, last_policy_epoch, total_events
            FROM devices
            WHERE device_id_pseudo=?
            """,
            (device_id_pseudo,),
        ).fetchone()
        if current is None:
            conn.execute(
                """
                INSERT INTO devices(
                    device_id_pseudo,
                    last_seen_epoch,
                    last_flow_epoch,
                    last_alert_epoch,
                    last_heartbeat_epoch,
                    last_policy_epoch,
                    total_events
                )
                VALUES (?, ?, 0, 0, ?, 0, 0)
                """,
                (device_id_pseudo, epoch, epoch),
            )
            return

        last_seen, last_flow, last_alert, last_heartbeat, last_policy, total_events = current
        conn.execute(
            """
            UPDATE devices
            SET last_seen_epoch=?,
                last_flow_epoch=?,
                last_alert_epoch=?,
                last_heartbeat_epoch=?,
                last_policy_epoch=?,
                total_events=?
            WHERE device_id_pseudo=?
            """,
            (
                max(int(last_seen or 0), epoch),
                int(last_flow or 0),
                int(last_alert or 0),
                max(int(last_heartbeat or 0), epoch),
                int(last_policy or 0),
                int(total_events or 0),
                device_id_pseudo,
            ),
        )

    def _upsert_device_metadata(
        self,
        conn: sqlite3.Connection,
        device_id_pseudo: str,
        *,
        observed_name: str | None = None,
        display_name: str | None = None,
        epoch: int,
    ) -> None:
        current = conn.execute(
            """
            SELECT observed_name, display_name, updated_epoch
            FROM device_metadata
            WHERE device_id_pseudo=?
            """,
            (device_id_pseudo,),
        ).fetchone()
        if current is None:
            conn.execute(
                """
                INSERT INTO device_metadata(device_id_pseudo, observed_name, display_name, updated_epoch)
                VALUES (?, ?, ?, ?)
                """,
                (device_id_pseudo, observed_name, display_name, epoch),
            )
            return

        current_observed, current_display, current_updated = current
        next_observed = observed_name if observed_name is not None else current_observed
        next_display = display_name if display_name is not None else current_display
        conn.execute(
            """
            UPDATE device_metadata
            SET observed_name=?, display_name=?, updated_epoch=?
            WHERE device_id_pseudo=?
            """,
            (
                next_observed,
                next_display,
                max(int(current_updated or 0), epoch),
                device_id_pseudo,
            ),
        )

    def _migrate_legacy_remote_models(self, conn: sqlite3.Connection) -> None:
        legacy_rows = conn.execute(
            "SELECT device_id_pseudo, model_json, updated_epoch FROM remote_models"
        ).fetchall()
        for device_id_pseudo, model_json, updated_epoch in legacy_rows:
            existing = conn.execute(
                """
                SELECT COUNT(*)
                FROM remote_model_registry
                WHERE device_id_pseudo=?
                """,
                (device_id_pseudo,),
            ).fetchone()[0]
            if existing:
                continue
            conn.execute(
                """
                INSERT OR REPLACE INTO remote_model_registry(
                    device_id_pseudo, version, model_json, training_job_id, created_epoch, activated_epoch, is_active
                ) VALUES (?, 1, ?, NULL, ?, ?, 1)
                """,
                (device_id_pseudo, model_json, updated_epoch, updated_epoch),
            )

    def _rebuild_device_index(self, conn: sqlite3.Connection) -> None:
        devices: dict[str, dict[str, int]] = {}

        def touch(
            device_id: str,
            *,
            seen: int = 0,
            flow: int = 0,
            alert: int = 0,
            heartbeat: int = 0,
            policy: int = 0,
            total: int = 0,
        ) -> None:
            if not device_id:
                return
            state = devices.setdefault(
                device_id,
                {
                    "last_seen_epoch": 0,
                    "last_flow_epoch": 0,
                    "last_alert_epoch": 0,
                    "last_heartbeat_epoch": 0,
                    "last_policy_epoch": 0,
                    "total_events": 0,
                },
            )
            state["last_seen_epoch"] = max(state["last_seen_epoch"], seen)
            state["last_flow_epoch"] = max(state["last_flow_epoch"], flow)
            state["last_alert_epoch"] = max(state["last_alert_epoch"], alert)
            state["last_heartbeat_epoch"] = max(state["last_heartbeat_epoch"], heartbeat)
            state["last_policy_epoch"] = max(state["last_policy_epoch"], policy)
            state["total_events"] += total

        for device_id, last_heartbeat_epoch in conn.execute(
            "SELECT device_id_pseudo, last_heartbeat_epoch FROM devices"
        ).fetchall():
            heartbeat = int(last_heartbeat_epoch or 0)
            touch(str(device_id or ""), seen=heartbeat, heartbeat=heartbeat, total=0)

        for payload_json, event_type, updated_epoch in conn.execute(
            "SELECT payload_json, event_type, updated_epoch FROM events"
        ).fetchall():
            try:
                payload = json.loads(payload_json or "{}")
            except Exception:  # noqa: BLE001
                payload = {}
            device_id = str(payload.get("device_id_pseudo") or "").strip()
            if event_type == "mobile_flow":
                touch(device_id, seen=int(updated_epoch or 0), flow=int(updated_epoch or 0), total=1)
            elif event_type == "mobile_alert":
                touch(device_id, seen=int(updated_epoch or 0), alert=int(updated_epoch or 0), total=1)

        for device_id, updated_epoch in conn.execute(
            "SELECT device_id_pseudo, MAX(updated_epoch) FROM alerts GROUP BY device_id_pseudo"
        ).fetchall():
            touch(str(device_id or ""), seen=int(updated_epoch or 0), alert=int(updated_epoch or 0), total=0)

        for device_id, updated_epoch in conn.execute(
            "SELECT device_id_pseudo, updated_epoch FROM policies"
        ).fetchall():
            if str(device_id or "") == "__global__":
                continue
            touch(str(device_id or ""), policy=int(updated_epoch or 0), total=0)

        conn.execute("DELETE FROM devices")
        for device_id, state in devices.items():
            conn.execute(
                """
                INSERT INTO devices(
                    device_id_pseudo,
                    last_seen_epoch,
                    last_flow_epoch,
                    last_alert_epoch,
                    last_heartbeat_epoch,
                    last_policy_epoch,
                    total_events
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    state["last_seen_epoch"],
                    state["last_flow_epoch"],
                    state["last_alert_epoch"],
                    state["last_heartbeat_epoch"],
                    state["last_policy_epoch"],
                    state["total_events"],
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._sqlite_path, check_same_thread=False)
