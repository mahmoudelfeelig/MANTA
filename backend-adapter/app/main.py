from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import BackgroundTasks, Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, status
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import load_settings
from .models import (
    AdminPurgeRequest,
    AdapterEventAck,
    AlertTriageUpdate,
    DeviceHeartbeatPayload,
    DeviceDisplayNameUpdate,
    DevicePolicyPayload,
    MobileAlertEvent,
    MobileFlowEvent,
    PolicyApplyScopeRequest,
    PolicySimulationRequest,
    RemoteInferenceRequest,
    RemoteModelUpsertRequest,
)
from .remote_modeling import default_remote_model, score_remote_model, train_remote_model
from .resistine_client import ResistineClient, ResistineConfig
from .security import require_auth, verify_token
from .storage import AdapterStorage, QueueItem
from .wazuh_client import WazuhClient, WazuhConfig


def _retry_delay_seconds(base: int, attempts: int) -> int:
    return min(300, base * (2 ** max(0, attempts - 1)))


def _severity_label(rank: int) -> str:
    if rank >= 3:
        return "HIGH"
    if rank == 2:
        return "MEDIUM"
    return "LOW"


_DASHBOARD_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "dashboards" / "dashboard.html"


def _load_dashboard_html() -> str:
    return _DASHBOARD_TEMPLATE_PATH.read_text(encoding="utf-8")


def _parse_device_filters(
    device_id_pseudo: str | None,
    device_ids_csv: str | None,
) -> list[str]:
    values: list[str] = []
    if device_id_pseudo:
        values.append(device_id_pseudo.strip())
    if device_ids_csv:
        values.extend(part.strip() for part in device_ids_csv.split(","))
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _alert_payload(alert) -> dict:
    payload = dict(alert.__dict__)
    raw_top_features = payload.pop("top_features_json", "[]")
    try:
        top_features = json.loads(raw_top_features) if raw_top_features else []
    except Exception:  # noqa: BLE001
        top_features = []
    if not isinstance(top_features, list):
        top_features = []
    raw_warnings = payload.pop("data_quality_warnings_json", "[]")
    try:
        warnings = json.loads(raw_warnings) if raw_warnings else []
    except Exception:  # noqa: BLE001
        warnings = []
    if not isinstance(warnings, list):
        warnings = []
    raw_feature_window = payload.pop("feature_window_json", "{}")
    try:
        feature_window = json.loads(raw_feature_window) if raw_feature_window else {}
    except Exception:  # noqa: BLE001
        feature_window = {}
    if not isinstance(feature_window, dict):
        feature_window = {}
    payload["top_features"] = [str(item) for item in top_features]
    payload["data_quality_warnings"] = [str(item) for item in warnings]
    payload["window_features"] = feature_window
    return payload


def _incident_payload(incident) -> dict:
    payload = dict(incident.__dict__)
    payload["max_severity"] = _severity_label(int(payload.get("max_severity_rank", 1)))
    return payload


def _remote_inference(payload: RemoteInferenceRequest) -> dict:
    model = storage.get_remote_model(payload.device_id_pseudo) or default_remote_model()
    scored = score_remote_model(
        model=model,
        feature_window=payload.feature_window.model_dump(mode="json"),
        site_hint=payload.site_hint,
    )
    feedback = storage.remote_feedback_adjustment(payload.app_id)
    adjusted_score = max(0.0, min(1.0, scored["score"] + feedback["score_bias"]))
    adjusted_confidence = max(0.0, min(1.0, scored["confidence"] + feedback["confidence_boost"]))
    diagnostics = dict(scored["diagnostics"])
    diagnostics.update(
        {
            "feedback_false_positive": feedback["false_positive"],
            "feedback_resolved": feedback["resolved"],
            "feedback_bias": feedback["score_bias"],
        }
    )
    return {
        "score": adjusted_score,
        "anomaly_score": float(scored.get("anomaly_score", scored["score"])),
        "context_score": float(scored.get("context_score", 0.0)),
        "response_score": adjusted_score,
        "top_features": scored["top_features"],
        "feature_contributions": scored["feature_contributions"],
        "confidence": adjusted_confidence,
        "uncertainty": 1.0 - adjusted_confidence,
        "diagnostics": diagnostics,
    }


def _model_families_from_versions(versions: list) -> list[str]:
    families: list[str] = []
    for item in versions:
        model = json.loads(item.model_json)
        family = str(model.get("model_family") or model.get("model_type") or "unknown")
        if family not in families:
            families.append(family)
    return families


def _train_remote_model_payload(device_id_pseudo: str, family: str = "logistic_regression") -> tuple[dict, int]:
    existing = storage.get_remote_model(device_id_pseudo)
    if existing is None or str(existing.get("model_family") or existing.get("model_type") or "") != family:
        existing = default_remote_model(model_type=family)
    samples = storage.export_retraining_samples(device_id_pseudo=device_id_pseudo, limit=5000)
    trained, report = train_remote_model(samples=samples, previous_model=existing, model_type=family)
    trained["training_report"] = report
    return trained, int(report["sample_count"])


def _execute_remote_model_job(job_id: str, device_id_pseudo: str, family: str = "logistic_regression") -> None:
    storage.mark_remote_model_job_running(job_id)
    try:
        model, sample_count = _train_remote_model_payload(device_id_pseudo, family=family)
        stored = storage.set_remote_model(
            device_id_pseudo=device_id_pseudo,
            model=model,
            activate=False,
            training_job_id=job_id,
        )
        storage.mark_remote_model_job_completed(
            job_id=job_id,
            sample_count=sample_count,
            output_version=int(stored.get("version", 0)),
        )
    except Exception as exc:  # noqa: BLE001
        storage.mark_remote_model_job_failed(job_id=job_id, error=str(exc))


settings = load_settings()
storage = AdapterStorage(settings.sqlite_path)
wazuh_client = WazuhClient(
    WazuhConfig(
        ingest_url=settings.wazuh_ingest_url,
        api_token=settings.wazuh_api_token,
        allow_insecure=settings.allow_insecure_wazuh,
    )
)
resistine_client = ResistineClient(
    ResistineConfig(
        base_url=settings.resistine_base_url,
        api_token=settings.resistine_api_token,
        allow_insecure=settings.allow_insecure_resistine,
    )
)
storage.initialize()
app = FastAPI(title="MANTA Backend Adapter", version="0.2.0")

_DASHBOARD_LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>MANTA Backend Login</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", "SF Pro Display", sans-serif;
      background: radial-gradient(circle at top, #1a252d, #0f1418 45%);
      color: #eef4f7;
    }
    .card {
      width: min(420px, 92vw);
      background: #182027;
      border: 1px solid #30404b;
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.22);
    }
    h1 { margin-top: 0; }
    p { color: #9eb1bc; }
    input, button {
      width: 100%;
      border-radius: 12px;
      border: 1px solid #30404b;
      background: #1f2a33;
      color: #eef4f7;
      padding: 12px;
      font: inherit;
      margin-top: 12px;
      box-sizing: border-box;
    }
    button {
      background: linear-gradient(180deg, #31b79b, #20937e);
      color: #06241f;
      font-weight: 700;
      cursor: pointer;
    }
    .error { color: #ff9d9d; margin-top: 10px; }
  </style>
</head>
<body>
  <form class="card" id="loginForm">
    <h1>MANTA Backend Viewer</h1>
    <p>Authenticate with the shared adapter token to open the protected dashboard.</p>
    <input type="password" id="tokenInput" placeholder="Shared adapter token" autofocus />
    <button type="submit">Open dashboard</button>
    <div id="errorBox">__ERROR_HTML__</div>
  </form>
  <script>
    document.getElementById("loginForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const token = document.getElementById("tokenInput").value;
      const response = await fetch("/dashboard/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token })
      });
      if (response.ok) {
        window.location.href = "/dashboard";
        return;
      }
      document.getElementById("errorBox").innerHTML = '<div class="error">Invalid token.</div>';
    });
  </script>
</body>
</html>
"""

_DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>MANTA Backend Viewer</title>
  <style>
    :root {
      --bg: #0f1418;
      --panel: #182027;
      --panel-alt: #1f2a33;
      --text: #eef4f7;
      --muted: #9eb1bc;
      --accent: #4dd0b4;
      --accent-2: #f5c86b;
      --danger: #ff7d7d;
      --border: #30404b;
      --chip: #24313a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", sans-serif;
      background: radial-gradient(circle at top, #1a252d, var(--bg) 45%);
      color: var(--text);
    }
    .wrap {
      max-width: 1480px;
      margin: 0 auto;
      padding: 24px;
    }
    h1, h2, h3 { margin: 0; }
    .hero {
      display: grid;
      gap: 16px;
      margin-bottom: 20px;
    }
    .hero-card, .panel {
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.22);
    }
    .hero-card p, .muted { color: var(--muted); }
    .toolbar {
      display: grid;
      grid-template-columns: 1.2fr 1fr 1fr 1fr auto;
      gap: 12px;
      align-items: end;
    }
    input, select, button, textarea {
      width: 100%;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      padding: 10px 12px;
      font: inherit;
    }
    button {
      cursor: pointer;
      background: linear-gradient(180deg, #31b79b, #20937e);
      color: #06241f;
      font-weight: 700;
    }
    button.secondary {
      background: var(--chip);
      color: var(--text);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 16px;
    }
    .span-3 { grid-column: span 3; }
    .span-4 { grid-column: span 4; }
    .span-5 { grid-column: span 5; }
    .span-6 { grid-column: span 6; }
    .span-7 { grid-column: span 7; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }
    .stats {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
    }
    .stat {
      background: var(--chip);
      border-radius: 14px;
      padding: 14px;
      border: 1px solid rgba(255,255,255,0.04);
    }
    .stat .value {
      font-size: 28px;
      font-weight: 800;
      margin-top: 6px;
    }
    .list, .table-wrap {
      max-height: 720px;
      overflow: auto;
    }
    .event-card, .alert-card {
      background: var(--chip);
      border-radius: 14px;
      padding: 14px;
      border: 1px solid rgba(255,255,255,0.04);
      margin-bottom: 12px;
    }
    .event-head, .alert-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .chip-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 8px 0;
    }
    .chip {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.08);
      color: var(--text);
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
    }
    .chip.sent { color: var(--accent); }
    .chip.pending { color: var(--accent-2); }
    .chip.high { color: var(--danger); }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: rgba(0,0,0,0.22);
      border-radius: 12px;
      padding: 12px;
      font-size: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      vertical-align: top;
    }
    th { color: var(--muted); position: sticky; top: 0; background: var(--panel); }
    .danger-text { color: var(--danger); }
    .small { font-size: 12px; }
    @media (max-width: 1100px) {
      .toolbar, .stats, .grid { grid-template-columns: 1fr; }
      .span-3, .span-4, .span-5, .span-6, .span-7, .span-8, .span-12 { grid-column: span 1; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="hero-card">
        <h1>MANTA Backend Viewer</h1>
        <p>Analyst-friendly viewer for exported mobile flows, alerts, incidents, queue state, and policy/inference activity.</p>
      </div>
      <div class="hero-card">
        <div class="toolbar">
          <label>
            <div class="muted small">Base URL</div>
            <input id="baseUrl" value="" placeholder="http://127.0.0.1:8080" />
          </label>
          <label>
            <div class="muted small">Token</div>
            <input id="token" type="password" placeholder="Bearer token" />
          </label>
          <label>
            <div class="muted small">Event type</div>
            <select id="eventType">
              <option value="">All events</option>
              <option value="mobile_flow">mobile_flow</option>
              <option value="mobile_alert">mobile_alert</option>
            </select>
          </label>
          <label>
            <div class="muted small">Status</div>
            <select id="eventStatus">
              <option value="">All</option>
              <option value="sent">sent</option>
              <option value="pending">pending</option>
            </select>
          </label>
          <label>
            <div class="muted small">Device</div>
            <select id="deviceFilter">
              <option value="">All devices</option>
            </select>
          </label>
          <button id="refreshBtn">Refresh</button>
        </div>
      </div>
    </div>

    <div class="grid">
      <section class="panel span-12">
        <h2>Queue & Health</h2>
        <div class="stats" id="stats"></div>
      </section>

      <section class="panel span-7">
        <div class="event-head">
          <h2>Recent Exported Events</h2>
          <button class="secondary" id="copyEventsBtn">Copy raw events JSON</button>
        </div>
        <div class="list" id="events"></div>
      </section>

      <section class="panel span-5">
        <div class="alert-head">
          <h2>Alerts</h2>
          <span class="muted small" id="alertsCount">0 items</span>
        </div>
        <div class="toolbar" style="grid-template-columns: 1fr 1fr 1fr 1.2fr auto; margin-bottom: 12px;">
          <label>
            <div class="muted small">Severity</div>
            <select id="severityFilter">
              <option value="">All severities</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </label>
          <label>
            <div class="muted small">Triage</div>
            <select id="triageFilter">
              <option value="">All</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </label>
          <label>
            <div class="muted small">Model</div>
            <input id="modelFilter" placeholder="source_model" />
          </label>
          <label>
            <div class="muted small">Search</div>
            <input id="searchFilter" placeholder="app, site, explanation, feature" />
          </label>
          <button class="secondary" id="clearAlertFiltersBtn">Reset</button>
        </div>
        <div class="list" id="alerts"></div>
      </section>

      <section class="panel span-6">
        <h2>Incidents</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Correlation</th><th>App</th><th>Alerts</th><th>Max severity</th><th>Latest</th></tr>
            </thead>
            <tbody id="incidents"></tbody>
          </table>
        </div>
      </section>

      <section class="panel span-6">
        <h2>Quality Summary</h2>
        <pre id="quality">No data yet.</pre>
      </section>

      <section class="panel span-12">
        <div class="event-head">
          <h2>Policy Editor</h2>
          <div class="chip-row">
            <span class="chip">device</span>
            <span class="chip">all devices</span>
            <span class="chip">global default</span>
          </div>
        </div>
        <p class="muted small">
          Policy controls the remotely managed detection subset: thresholds, export flag, detection/shadow model,
          false-positive budget, retention, and drift threshold. Theme, debug mode, privacy variant, evidence capture,
          app profiles, and local ablation remain phone-local settings.
        </p>
        <div class="toolbar" style="grid-template-columns: 1fr 1fr 1fr auto; margin-bottom: 12px;">
          <label>
            <div class="muted small">Apply scope</div>
            <select id="policyScope">
              <option value="device">Selected device</option>
              <option value="all_devices">All known devices</option>
              <option value="global_default">Global default</option>
            </select>
          </label>
          <label>
            <div class="muted small">Detection model</div>
            <select id="policyDetectionModel">
              <option value="ensemble_fusion">ensemble_fusion</option>
              <option value="statistical">statistical</option>
              <option value="multivariate">multivariate</option>
              <option value="sequence">sequence</option>
              <option value="linear">linear</option>
              <option value="tflite">tflite</option>
              <option value="remote_assisted">remote_assisted</option>
            </select>
          </label>
          <label>
            <div class="muted small">Shadow model</div>
            <select id="policyShadowModel">
              <option value="">disabled</option>
              <option value="ensemble_fusion">ensemble_fusion</option>
              <option value="statistical">statistical</option>
              <option value="multivariate">multivariate</option>
              <option value="sequence">sequence</option>
              <option value="linear">linear</option>
              <option value="tflite">tflite</option>
              <option value="remote_assisted">remote_assisted</option>
            </select>
          </label>
          <button id="loadPolicyBtn" class="secondary">Load policy</button>
        </div>
        <div class="grid">
          <div class="span-3">
            <label><div class="muted small">Medium threshold</div><input id="policyMedium" value="0.60" /></label>
          </div>
          <div class="span-3">
            <label><div class="muted small">High threshold</div><input id="policyHigh" value="0.85" /></label>
          </div>
          <div class="span-3">
            <label><div class="muted small">Retention days</div><input id="policyRetention" value="7" /></label>
          </div>
          <div class="span-3">
            <label><div class="muted small">FP budget/app/day</div><input id="policyBudget" value="12" /></label>
          </div>
          <div class="span-3">
            <label><div class="muted small">Drift high threshold</div><input id="policyDrift" value="0.65" /></label>
          </div>
          <div class="span-3">
            <label><div class="muted small">Export enabled</div><select id="policyExportEnabled"><option value="true">true</option><option value="false">false</option></select></label>
          </div>
        </div>
        <div class="chip-row" style="margin-top: 12px;">
          <button id="savePolicyBtn">Save policy</button>
        </div>
        <pre id="policyEditorOutput">No policy loaded.</pre>
      </section>

      <section class="panel span-12">
        <div class="event-head">
          <h2>Remote Model Control</h2>
          <div class="chip-row">
            <span class="chip">remote-assisted inference</span>
          </div>
        </div>
        <p class="muted small">
          Retraining updates the backend remote-assisted model for the selected device. Multiple remote model
          families can coexist in the registry, and activating a different version changes the current remote
          scorer for that device. This affects <code>remote_assisted</code> directly and the
          <code>remote</code> contribution inside <code>ensemble_fusion</code>.
        </p>
        <div class="toolbar" style="grid-template-columns: 1.2fr auto auto;">
          <label>
            <div class="muted small">Device policy ID</div>
            <input id="deviceId" placeholder="paste device_id_pseudo here" />
          </label>
          <button id="loadModelBtn" class="secondary">Load model</button>
          <button id="retrainModelBtn">Retrain model</button>
        </div>
        <pre id="remoteModel">No model loaded.</pre>
        <div class="grid" style="margin-top: 12px;">
          <div class="span-6">
            <h3>Model registry</h3>
            <pre id="remoteRegistry">No versions loaded.</pre>
          </div>
          <div class="span-6">
            <h3>Training jobs</h3>
            <pre id="remoteJobs">No jobs loaded.</pre>
          </div>
        </div>
      </section>
    </div>
  </div>

  <script>
    const els = {
      baseUrl: document.getElementById("baseUrl"),
      token: document.getElementById("token"),
      eventType: document.getElementById("eventType"),
      eventStatus: document.getElementById("eventStatus"),
      deviceFilter: document.getElementById("deviceFilter"),
      refreshBtn: document.getElementById("refreshBtn"),
      stats: document.getElementById("stats"),
      events: document.getElementById("events"),
      alerts: document.getElementById("alerts"),
      alertsCount: document.getElementById("alertsCount"),
      severityFilter: document.getElementById("severityFilter"),
      triageFilter: document.getElementById("triageFilter"),
      modelFilter: document.getElementById("modelFilter"),
      searchFilter: document.getElementById("searchFilter"),
      clearAlertFiltersBtn: document.getElementById("clearAlertFiltersBtn"),
      incidents: document.getElementById("incidents"),
      quality: document.getElementById("quality"),
      policyScope: document.getElementById("policyScope"),
      policyDetectionModel: document.getElementById("policyDetectionModel"),
      policyShadowModel: document.getElementById("policyShadowModel"),
      policyMedium: document.getElementById("policyMedium"),
      policyHigh: document.getElementById("policyHigh"),
      policyRetention: document.getElementById("policyRetention"),
      policyBudget: document.getElementById("policyBudget"),
      policyDrift: document.getElementById("policyDrift"),
      policyExportEnabled: document.getElementById("policyExportEnabled"),
      loadPolicyBtn: document.getElementById("loadPolicyBtn"),
      savePolicyBtn: document.getElementById("savePolicyBtn"),
      policyEditorOutput: document.getElementById("policyEditorOutput"),
      copyEventsBtn: document.getElementById("copyEventsBtn"),
      deviceId: document.getElementById("deviceId"),
      loadModelBtn: document.getElementById("loadModelBtn"),
      retrainModelBtn: document.getElementById("retrainModelBtn"),
      remoteModel: document.getElementById("remoteModel"),
      remoteRegistry: document.getElementById("remoteRegistry"),
      remoteJobs: document.getElementById("remoteJobs")
    };

    els.baseUrl.value = window.location.origin;

    async function api(path) {
      const headers = {};
      const token = els.token.value.trim();
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const response = await fetch(`${els.baseUrl.value.trim()}${path}`, { headers });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      return response.json();
    }

    function statCard(label, value) {
      return `<div class="stat"><div class="muted small">${label}</div><div class="value">${value}</div></div>`;
    }

    function formatTs(epoch) {
      if (!epoch) return "-";
      return new Date(epoch * 1000).toLocaleString();
    }

    function renderStats(health) {
      const q = health.queue || {};
      els.stats.innerHTML = [
        statCard("Pending", q.pending ?? 0),
        statCard("Sent", q.sent ?? 0),
        statCard("Dead letter", q.dead_letter ?? 0),
        statCard("Alerts", q.alerts ?? 0),
        statCard("Policies", q.policies ?? 0)
      ].join("");
    }

    function populateDevices(devices) {
      const current = els.deviceFilter.value;
      const currentModel = els.deviceId.value;
      const options = ['<option value="">All devices</option>'].concat(
        devices.map(device => {
          const label = `${device.device_id_pseudo}${device.online ? " (online)" : ""}`;
          return `<option value="${device.device_id_pseudo}">${label}</option>`;
        })
      );
      els.deviceFilter.innerHTML = options.join("");
      if (current) els.deviceFilter.value = current;

      const modelOptions = ['<option value="">Select device</option>'].concat(
        devices.map(device => {
          const label = `${device.device_id_pseudo}${device.online ? " (online)" : ""}`;
          return `<option value="${device.device_id_pseudo}">${label}</option>`;
        })
      );
      els.deviceId.innerHTML = "";
      const select = document.createElement("select");
      select.id = "deviceId";
      select.innerHTML = modelOptions.join("");
      if (currentModel) select.value = currentModel;
      els.deviceId.replaceWith(select);
      els.deviceId = select;
    }

    function eventSummary(payload) {
      if (!payload) return "No payload";
      if (payload.event_type === "mobile_flow") {
        return `${payload.app_id} -> ${payload.dst_ip || payload.dst_host_hash}:${payload.dst_port} (${payload.protocol})`;
      }
      if (payload.event_type === "mobile_alert") {
        return `${payload.app_id} ${payload.severity} score=${payload.anomaly_score}`;
      }
      return JSON.stringify(payload);
    }

    function renderEvents(items) {
      if (!items.length) {
        els.events.innerHTML = `<p class="muted">No events found for the current filter.</p>`;
        return;
      }
      els.events.innerHTML = items.map(item => `
        <div class="event-card">
          <div class="event-head">
            <strong>${item.event_type}</strong>
            <div class="chip-row">
              <span class="chip ${item.status}">${item.status}</span>
              <span class="chip">attempts ${item.attempts}</span>
              <span class="chip">${formatTs(item.updated_epoch)}</span>
            </div>
          </div>
          <div>${eventSummary(item.payload)}</div>
          ${item.last_error ? `<div class="danger-text small">Last error: ${item.last_error}</div>` : ""}
          <pre>${JSON.stringify(item.payload, null, 2)}</pre>
        </div>
      `).join("");
    }

    function renderAlerts(items) {
      els.alertsCount.textContent = `${items.length} items`;
      if (!items.length) {
        els.alerts.innerHTML = `<p class="muted">No alerts found.</p>`;
        return;
      }
      els.alerts.innerHTML = items.map(alert => `
        <div class="alert-card">
          <div class="alert-head">
            <strong>${alert.app_id}</strong>
            <div class="chip-row">
              <span class="chip ${String(alert.severity).toLowerCase()}">${alert.severity}</span>
              <span class="chip">${alert.triage_status}</span>
              <span class="chip">${alert.source_model}</span>
            </div>
          </div>
          <div class="small muted">${alert.explanation}</div>
          <div class="chip-row">
            ${(alert.top_features || []).map(f => `<span class="chip">${f}</span>`).join("")}
          </div>
        </div>
      `).join("");
    }

    function renderIncidents(items) {
      if (!items.length) {
        els.incidents.innerHTML = `<tr><td colspan="5" class="muted">No incidents yet.</td></tr>`;
        return;
      }
      els.incidents.innerHTML = items.map(item => `
        <tr>
          <td>${item.correlation_key}</td>
          <td>${item.app_id}</td>
          <td>${item.alert_count}</td>
          <td>${item.max_severity}</td>
          <td>${formatTs(item.latest_seen_epoch)}</td>
        </tr>
      `).join("");
    }

    async function refresh() {
      try {
        const params = new URLSearchParams();
        if (els.eventStatus.value) params.set("status", els.eventStatus.value);
        if (els.eventType.value) params.set("event_type", els.eventType.value);
        if (els.deviceFilter.value) params.set("device_id_pseudo", els.deviceFilter.value);
        params.set("limit", "100");

        const alertParams = new URLSearchParams();
        if (els.triageFilter.value) alertParams.set("triage_status", els.triageFilter.value);
        if (els.deviceFilter.value) alertParams.set("device_id_pseudo", els.deviceFilter.value);
        if (els.severityFilter.value) alertParams.set("severity", els.severityFilter.value);
        if (els.modelFilter.value.trim()) alertParams.set("source_model", els.modelFilter.value.trim());
        if (els.searchFilter.value.trim()) alertParams.set("search", els.searchFilter.value.trim());
        alertParams.set("limit", "200");

        const [health, events, alerts, incidents, quality, devices] = await Promise.all([
          api("/health"),
          api(`/api/v1/events/recent?${params.toString()}`),
          api(`/api/v1/alerts?${alertParams.toString()}`),
          api(`/api/v1/incidents?limit=50${els.deviceFilter.value ? `&device_id_pseudo=${encodeURIComponent(els.deviceFilter.value)}` : ""}`),
          api(`/api/v1/quality/summary${els.deviceFilter.value ? `?device_id_pseudo=${encodeURIComponent(els.deviceFilter.value)}` : ""}`),
          api("/api/v1/devices?limit=200")
        ]);

        renderStats(health);
        renderEvents(events.events || []);
        renderAlerts(alerts.alerts || []);
        renderIncidents(incidents.incidents || []);
        els.quality.textContent = JSON.stringify(quality.quality || {}, null, 2);
        populateDevices(devices.devices || []);

        els.copyEventsBtn.onclick = async () => {
          await navigator.clipboard.writeText(JSON.stringify(events.events || [], null, 2));
        };
      } catch (error) {
        els.events.innerHTML = `<div class="danger-text">Request failed: ${error.message}</div>`;
      }
    }

    async function loadRemoteModel(retrain = false) {
      const deviceId = els.deviceId.value.trim();
      if (!deviceId) {
        els.remoteModel.textContent = "Enter a device policy ID first.";
        return;
      }
      const call = async (path, method = "GET") => {
        const headers = {};
        const token = els.token.value.trim();
        if (token) headers["Authorization"] = `Bearer ${token}`;
        const response = await fetch(`${els.baseUrl.value.trim()}${path}`, { method, headers });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || `${response.status} ${response.statusText}`);
        }
        return payload;
      };

      if (retrain) {
        await call(`/api/v1/model/device/${encodeURIComponent(deviceId)}/retrain`, "POST");
      }

      const [modelPayload, registryPayload, jobsPayload] = await Promise.all([
        call(`/api/v1/model/device/${encodeURIComponent(deviceId)}`),
        call(`/api/v1/model/device/${encodeURIComponent(deviceId)}/registry?limit=20`),
        call(`/api/v1/model/device/${encodeURIComponent(deviceId)}/jobs?limit=20`)
      ]);

      els.remoteModel.textContent = JSON.stringify(modelPayload, null, 2);
      els.remoteRegistry.textContent = JSON.stringify(registryPayload, null, 2);
      els.remoteJobs.textContent = JSON.stringify(jobsPayload, null, 2);
    }

    async function loadPolicy() {
      const scope = els.policyScope.value;
      const selectedDevice = els.deviceFilter.value || els.deviceId.value;
      const path = scope === "global_default"
        ? "/api/v1/policy/device/__global__"
        : `/api/v1/policy/device/${encodeURIComponent(selectedDevice)}`;
      const payload = await api(path);
      const policy = payload.policy || {};
      els.policyMedium.value = policy.default_thresholds?.medium ?? 0.6;
      els.policyHigh.value = policy.default_thresholds?.high ?? 0.85;
      els.policyRetention.value = policy.retention_days ?? 7;
      els.policyBudget.value = policy.false_positive_budget_per_app_day ?? 12;
      els.policyDrift.value = policy.drift_high_threshold ?? 0.65;
      els.policyExportEnabled.value = String(policy.export_enabled ?? true);
      els.policyDetectionModel.value = policy.detection_model ?? "ensemble_fusion";
      els.policyShadowModel.value = policy.shadow_model ?? "";
      const fusion = policy.fusion_weights ?? {};
      if (els.fusionStat) {
        els.fusionStat.value = fusion.statistical ?? 0.28;
        els.fusionMultivariate.value = fusion.multivariate ?? 0.20;
        els.fusionSequence.value = fusion.sequence ?? 0.12;
        els.fusionLinear.value = fusion.linear ?? 0.16;
        els.fusionTflite.value = fusion.tflite ?? 0.12;
        els.fusionRemote.value = fusion.remote ?? 0.12;
        els.fusionBeacon.value = fusion.beacon ?? 0.15;
        els.fusionDrift.value = fusion.drift ?? 0.10;
        els.fusionReputation.value = fusion.reputation ?? 0.18;
        els.fusionDataQuality.value = fusion.data_quality_penalty ?? 0.10;
        els.fusionResponseAnomaly.value = fusion.response_anomaly ?? 0.82;
        els.fusionResponseContext.value = fusion.response_context ?? 0.18;
      }
      els.policyEditorOutput.textContent = JSON.stringify(payload, null, 2);
    }

    async function savePolicy() {
      const scope = els.policyScope.value;
      const selectedDevice = els.deviceFilter.value || els.deviceId.value;
      const body = {
        scope,
        device_ids: selectedDevice ? [selectedDevice] : [],
        policy: {
          policy_version: 1,
          default_thresholds: {
            medium: parseFloat(els.policyMedium.value),
            high: parseFloat(els.policyHigh.value)
          },
          app_threshold_overrides: {},
          export_enabled: els.policyExportEnabled.value === "true",
          retention_days: parseInt(els.policyRetention.value, 10),
          detection_model: els.policyDetectionModel.value,
          shadow_model: els.policyShadowModel.value || null,
          false_positive_budget_per_app_day: parseInt(els.policyBudget.value, 10),
          drift_high_threshold: parseFloat(els.policyDrift.value)
        }
      };
      if (els.fusionStat) {
        body.policy.fusion_weights = {
          statistical: parseFloat(els.fusionStat.value),
          multivariate: parseFloat(els.fusionMultivariate.value),
          sequence: parseFloat(els.fusionSequence.value),
          linear: parseFloat(els.fusionLinear.value),
          tflite: parseFloat(els.fusionTflite.value),
          remote: parseFloat(els.fusionRemote.value),
          beacon: parseFloat(els.fusionBeacon.value),
          drift: parseFloat(els.fusionDrift.value),
          reputation: parseFloat(els.fusionReputation.value),
          data_quality_penalty: parseFloat(els.fusionDataQuality.value),
          response_anomaly: parseFloat(els.fusionResponseAnomaly.value),
          response_context: parseFloat(els.fusionResponseContext.value)
        };
      }
      const token = els.token.value.trim();
      const response = await fetch(`${els.baseUrl.value.trim()}/api/v1/policy/apply`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { "Authorization": `Bearer ${token}` } : {})
        },
        body: JSON.stringify(body)
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || `${response.status} ${response.statusText}`);
      }
      els.policyEditorOutput.textContent = JSON.stringify(payload, null, 2);
    }

    els.refreshBtn.addEventListener("click", refresh);
    els.clearAlertFiltersBtn.addEventListener("click", () => {
      els.severityFilter.value = "";
      els.triageFilter.value = "";
      els.modelFilter.value = "";
      els.searchFilter.value = "";
      refresh();
    });
    els.deviceFilter.addEventListener("change", refresh);
    els.loadPolicyBtn.addEventListener("click", () => loadPolicy().catch(err => {
      els.policyEditorOutput.textContent = `Failed to load policy: ${err.message}`;
    }));
    els.savePolicyBtn.addEventListener("click", () => savePolicy().catch(err => {
      els.policyEditorOutput.textContent = `Failed to save policy: ${err.message}`;
    }));
    els.loadModelBtn.addEventListener("click", () => loadRemoteModel(false).catch(err => {
      els.remoteModel.textContent = `Failed to load model: ${err.message}`;
    }));
    els.retrainModelBtn.addEventListener("click", () => loadRemoteModel(true).catch(err => {
      els.remoteModel.textContent = `Failed to retrain model: ${err.message}`;
    }));
    refresh();
  </script>
</body>
</html>
"""


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/dashboard/login", response_class=HTMLResponse)
def dashboard_login_page(error: str | None = None) -> str:
    error_html = f'<div class="error">{error}</div>' if error else ""
    return _DASHBOARD_LOGIN_HTML.replace("__ERROR_HTML__", error_html)


@app.post("/dashboard/login")
async def dashboard_login(
    request: Request,
):
    payload = await request.json()
    token = str(payload.get("token") or "").strip()
    try:
        verify_token(settings.shared_token, token)
    except HTTPException:
        return Response(status_code=401)

    response = Response(status_code=204)
    response.set_cookie(
        key="dashboard_session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=8 * 60 * 60,
    )
    return response


@app.post("/dashboard/logout")
def dashboard_logout():
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    response.delete_cookie("dashboard_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(dashboard_session: str | None = Cookie(default=None)):
    try:
        verify_token(settings.shared_token, dashboard_session or "")
    except HTTPException:
        return RedirectResponse(url="/dashboard/login", status_code=303)
    return _load_dashboard_html()


def auth_dependency(
    authorization: str | None = Header(default=None),
    x_endpoint_token: str | None = Header(default=None),
    dashboard_session: str | None = Cookie(default=None),
) -> None:
    require_auth(
        expected_token=settings.shared_token,
        authorization=authorization,
        x_endpoint_token=x_endpoint_token,
        dashboard_session=dashboard_session,
    )


def _validate_payload_size(request: Request) -> None:
    body_size = int(request.headers.get("content-length", "0") or 0)
    if body_size > settings.max_event_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds maximum allowed size",
        )


def _enqueue_and_try_forward(event_type: str, payload: dict) -> tuple[str, bool]:
    event_id = str(uuid.uuid4())
    storage.enqueue_event(event_id=event_id, event_type=event_type, payload=payload)

    pending_items = storage.pending_events(now_epoch=int(time.time()), limit=1)
    forwarded = False
    if pending_items:
        _process_pending_item(pending_items[0])
        refreshed = storage.pending_events(now_epoch=int(time.time()), limit=1)
        # If queue head changed, likely the previous item was sent/dead-lettered.
        forwarded = not refreshed or refreshed[0].event_id != pending_items[0].event_id

    return event_id, forwarded


def _process_pending_item(item: QueueItem) -> None:
    try:
        wazuh_client.send(item.payload_json)
        storage.mark_sent(item.event_id)
    except Exception as exc:  # noqa: BLE001
        attempts = item.attempts + 1
        if attempts >= settings.max_retries:
            storage.move_to_dead_letter(item.event_id, item.event_type, item.payload_json, str(exc))
        else:
            next_epoch = int(time.time()) + _retry_delay_seconds(settings.retry_base_seconds, attempts)
            storage.mark_retry(item.event_id, attempts, next_epoch, str(exc))


@app.get("/health")
def health() -> dict:
    config_warnings: list[str] = []
    if len(settings.shared_token) < 16:
        config_warnings.append("ADAPTER_SHARED_TOKEN is shorter than recommended minimum length (16)")

    return {
        "status": "ok",
        "wazuh_configured": wazuh_client.configured(),
        "resistine_configured": resistine_client.configured(),
        "config_warnings": config_warnings,
        "queue": storage.stats(),
    }


@app.post("/api/v1/events/mobile-flow", status_code=status.HTTP_202_ACCEPTED, response_model=AdapterEventAck)
async def ingest_mobile_flow(
    request: Request,
    event: MobileFlowEvent,
    _: None = Depends(auth_dependency),
):
    _validate_payload_size(request)

    event_id, forwarded = _enqueue_and_try_forward(
        event_type="mobile_flow",
        payload=event.model_dump(mode="json"),
    )
    return AdapterEventAck(status="accepted", event_id=event_id, forwarded=forwarded)


@app.post("/api/v1/events/mobile-alert", status_code=status.HTTP_202_ACCEPTED, response_model=AdapterEventAck)
async def ingest_mobile_alert(
    request: Request,
    event: MobileAlertEvent,
    _: None = Depends(auth_dependency),
):
    _validate_payload_size(request)

    payload = event.model_dump(mode="json")
    storage.upsert_alert(payload)

    event_id, forwarded = _enqueue_and_try_forward(
        event_type="mobile_alert",
        payload=payload,
    )
    return AdapterEventAck(status="accepted", event_id=event_id, forwarded=forwarded)


@app.post("/api/v1/device/heartbeat")
def device_heartbeat(
    payload: DeviceHeartbeatPayload,
    _: None = Depends(auth_dependency),
):
    storage.note_device_heartbeat(
        payload.device_id_pseudo,
        observed_name=payload.device_label,
    )
    return {
        "status": "ok",
        "device_id_pseudo": payload.device_id_pseudo,
        "device_name": payload.device_label or payload.device_id_pseudo,
        "capture_enabled": payload.capture_enabled,
        "export_enabled": payload.export_enabled,
        "policy_version": payload.policy_version,
        "recorded_epoch": int(time.time()),
    }


@app.post("/api/v1/inference/window")
def infer_remote_window(
    payload: RemoteInferenceRequest,
    _: None = Depends(auth_dependency),
):
    storage.note_device_seen(payload.device_id_pseudo)
    result = _remote_inference(payload)
    return {
        "status": "ok",
        **result,
    }


@app.get("/api/v1/model/device/{device_id_pseudo}")
def get_remote_model(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    model = storage.get_remote_model(device_id_pseudo) or default_remote_model()
    versions = storage.list_remote_model_versions(device_id_pseudo=device_id_pseudo, limit=20)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "model": model,
        "available_families": _model_families_from_versions(versions),
        "versions": [
            {
                "version": item.version,
                "training_job_id": item.training_job_id,
                "created_epoch": item.created_epoch,
                "activated_epoch": item.activated_epoch,
                "is_active": bool(item.is_active),
            }
            for item in versions
        ],
    }


@app.put("/api/v1/model/device/{device_id_pseudo}")
def upsert_remote_model(
    device_id_pseudo: str,
    payload: RemoteModelUpsertRequest,
    _: None = Depends(auth_dependency),
):
    model = dict(payload.model)
    if payload.family and "model_family" not in model:
        model["model_family"] = payload.family
    stored = storage.set_remote_model(
        device_id_pseudo=device_id_pseudo,
        model=model,
        activate=payload.activate,
    )
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "model": stored,
    }


@app.get("/api/v1/model/device/{device_id_pseudo}/registry")
def list_remote_model_registry(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    _: None = Depends(auth_dependency),
):
    versions = storage.list_remote_model_versions(device_id_pseudo=device_id_pseudo, limit=limit)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "versions": [
            {
                "version": item.version,
                "model": json.loads(item.model_json),
                "training_job_id": item.training_job_id,
                "created_epoch": item.created_epoch,
                "activated_epoch": item.activated_epoch,
                "is_active": bool(item.is_active),
            }
            for item in versions
        ],
    }


@app.get("/api/v1/model/device/{device_id_pseudo}/families")
def list_remote_model_families(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    versions = storage.list_remote_model_versions(device_id_pseudo=device_id_pseudo, limit=200)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "families": _model_families_from_versions(versions),
    }


@app.post("/api/v1/model/device/{device_id_pseudo}/registry/{version}/activate")
def activate_remote_model_version(
    device_id_pseudo: str,
    version: int,
    _: None = Depends(auth_dependency),
):
    model = storage.activate_remote_model_version(device_id_pseudo=device_id_pseudo, version=version)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remote model version not found")
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "model": model,
    }


@app.get("/api/v1/model/device/{device_id_pseudo}/jobs")
def list_remote_model_jobs(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    _: None = Depends(auth_dependency),
):
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "jobs": [
            {
                "job_id": item.job_id,
                "status": item.status,
                "created_epoch": item.created_epoch,
                "started_epoch": item.started_epoch,
                "completed_epoch": item.completed_epoch,
                "error": item.error,
                "sample_count": item.sample_count,
                "output_version": item.output_version,
            }
            for item in storage.list_remote_model_jobs(device_id_pseudo=device_id_pseudo, limit=limit)
        ],
    }
    

@app.post("/api/v1/model/device/{device_id_pseudo}/jobs/retrain")
def queue_remote_model_retrain(
    device_id_pseudo: str,
    background_tasks: BackgroundTasks,
    family: Annotated[str, Query(pattern="^(logistic_regression|mahalanobis_covariance|hybrid_dual_channel)$")] = "logistic_regression",
    _: None = Depends(auth_dependency),
):
    job_id = str(uuid.uuid4())
    storage.create_remote_model_job(job_id=job_id, device_id_pseudo=device_id_pseudo)
    background_tasks.add_task(_execute_remote_model_job, job_id, device_id_pseudo, family)
    return {
        "status": "queued",
        "device_id_pseudo": device_id_pseudo,
        "job_id": job_id,
        "family": family,
    }
    

@app.post("/api/v1/model/device/{device_id_pseudo}/retrain")
def retrain_remote_model_immediately(
    device_id_pseudo: str,
    family: Annotated[str, Query(pattern="^(logistic_regression|mahalanobis_covariance|hybrid_dual_channel)$")] = "logistic_regression",
    _: None = Depends(auth_dependency),
):
    try:
        model, sample_count = _train_remote_model_payload(device_id_pseudo, family=family)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    stored = storage.set_remote_model(device_id_pseudo=device_id_pseudo, model=model, activate=True)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "family": family,
        "sample_count": sample_count,
        "model": stored,
    }


@app.post("/api/v1/events/retry")
def retry_pending(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    now = int(time.time())
    pending = storage.pending_events(now_epoch=now, limit=limit)

    sent = 0
    failed = 0
    for item in pending:
        before_stats = storage.stats()
        _process_pending_item(item)
        after_stats = storage.stats()
        if after_stats["sent"] > before_stats["sent"]:
            sent += 1
        else:
            failed += 1

    return {
        "status": "ok",
        "processed": len(pending),
        "sent": sent,
        "failed": failed,
    }


@app.get("/api/v1/queue/pending")
def list_pending_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    records = storage.list_pending(limit=limit)
    return {
        "status": "ok",
        "pending": [record.__dict__ for record in records],
    }


@app.get("/api/v1/queue/dead-letter")
def list_dead_letter_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    records = storage.list_dead_letter(limit=limit)
    return {
        "status": "ok",
        "dead_letter": [record.__dict__ for record in records],
    }


@app.get("/api/v1/events/recent")
def list_recent_events(
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    event_type: Annotated[str | None, Query()] = None,
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    device_ids: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    if status_filter is not None and status_filter not in {"pending", "sent"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status filter")

    records = storage.list_events(
        status=status_filter,
        limit=limit,
        event_type=event_type,
        device_id_pseudo=device_id_pseudo,
        device_ids=_parse_device_filters(device_id_pseudo, device_ids),
    )
    events = []
    for record in records:
        payload = json.loads(record.payload_json)
        events.append(
            {
                "event_id": record.event_id,
                "event_type": record.event_type,
                "status": record.status,
                "attempts": record.attempts,
                "last_error": record.last_error,
                "created_epoch": record.created_epoch,
                "updated_epoch": record.updated_epoch,
                "payload": payload,
            }
        )

    return {
        "status": "ok",
        "events": events,
    }


@app.post("/api/v1/queue/dead-letter/replay")
def replay_dead_letter_queue(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    moved = storage.replay_dead_letter(limit=limit)
    return {
        "status": "ok",
        "replayed": moved,
        "queue": storage.stats(),
    }


@app.post("/api/v1/resistine/register")
def resistine_register(
    payload: dict,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.register_endpoint(payload)
    return {"status": "ok", "response": response}


@app.get("/api/v1/resistine/connection/{device_id}")
def resistine_connection(
    device_id: str,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.get_connection(device_id=device_id)
    return {"status": "ok", "response": response}


@app.post("/api/v1/resistine/send/{stream_id}")
def resistine_send_data(
    stream_id: str,
    payload: dict,
    _: None = Depends(auth_dependency),
):
    if not resistine_client.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Resistine is not configured")
    response = resistine_client.send_data(stream_id=stream_id, payload=payload)
    return {"status": "ok", "response": response}


@app.get("/api/v1/alerts")
def list_alerts(
    triage_status: Annotated[str | None, Query()] = None,
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    device_ids: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    source_model: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    _: None = Depends(auth_dependency),
):
    if triage_status is not None and triage_status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid triage status")
    if severity is not None and severity not in {"LOW", "MEDIUM", "HIGH"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid severity")

    alerts = storage.list_alerts(
        status=triage_status,
        limit=limit,
        device_id_pseudo=device_id_pseudo,
        device_ids=_parse_device_filters(device_id_pseudo, device_ids),
        severity=severity,
        source_model=source_model,
        search=search,
    )
    return {
        "status": "ok",
        "alerts": [_alert_payload(alert) for alert in alerts],
    }


@app.get("/api/v1/incidents")
def list_incidents(
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    device_ids: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 250,
    _: None = Depends(auth_dependency),
):
    incidents = storage.list_incidents(
        limit=limit,
        device_id_pseudo=device_id_pseudo,
        device_ids=_parse_device_filters(device_id_pseudo, device_ids),
    )
    return {
        "status": "ok",
        "incidents": [_incident_payload(incident) for incident in incidents],
    }


@app.get("/api/v1/quality/summary")
def quality_summary(
    device_id_pseudo: Annotated[str | None, Query(min_length=8, max_length=128)] = None,
    device_ids: Annotated[str | None, Query()] = None,
    _: None = Depends(auth_dependency),
):
    summary = storage.quality_summary(
        device_id_pseudo=device_id_pseudo,
        device_ids=_parse_device_filters(device_id_pseudo, device_ids),
    )
    return {
        "status": "ok",
        "quality": summary,
    }


@app.get("/api/v1/devices")
def list_devices(
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    _: None = Depends(auth_dependency),
):
    now = int(time.time())
    storage.refresh_device_index()
    devices = storage.list_devices(limit=limit)
    def activity_source(item) -> str:
        points = {
            "flow": int(item.last_flow_epoch or 0),
            "alert": int(item.last_alert_epoch or 0),
            "heartbeat": int(item.last_heartbeat_epoch or 0),
            "policy": int(item.last_policy_epoch or 0),
        }
        source, epoch = max(points.items(), key=lambda pair: pair[1])
        return source if epoch > 0 else "unknown"

    def last_activity_epoch(item) -> int:
        return max(
            int(item.last_flow_epoch or 0),
            int(item.last_alert_epoch or 0),
            int(item.last_heartbeat_epoch or 0),
        )

    def online_window_seconds(item) -> int:
        last_heartbeat = int(item.last_heartbeat_epoch or 0)
        if last_heartbeat and last_heartbeat >= last_activity_epoch(item):
            return 20 * 60
        return 10 * 60

    return {
        "status": "ok",
        "devices": [
            {
                "device_rank": index + 1,
                "device_id_pseudo": item.device_id_pseudo,
                "observed_name": item.observed_name,
                "display_name": item.display_name,
                "device_name": item.display_name or item.observed_name or item.device_id_pseudo,
                "metadata_updated_epoch": item.metadata_updated_epoch,
                "last_seen_epoch": item.last_seen_epoch,
                "last_flow_epoch": item.last_flow_epoch,
                "last_alert_epoch": item.last_alert_epoch,
                "last_heartbeat_epoch": item.last_heartbeat_epoch,
                "last_policy_epoch": item.last_policy_epoch,
                "last_activity_epoch": last_activity_epoch(item),
                "total_events": item.total_events,
                "has_policy": storage.get_policy(item.device_id_pseudo) is not None,
                "online": (now - last_activity_epoch(item)) <= online_window_seconds(item) if last_activity_epoch(item) else False,
                "status_label": (
                    "online"
                    if last_activity_epoch(item) and (now - last_activity_epoch(item)) <= online_window_seconds(item)
                    else "recent"
                    if last_activity_epoch(item) and (now - last_activity_epoch(item)) <= 60 * 60
                    else "stale"
                ),
                "activity_source": activity_source(item),
                "minutes_since_seen": int((now - last_activity_epoch(item)) / 60) if last_activity_epoch(item) else None,
            }
            for index, item in enumerate(devices)
        ],
    }


@app.patch("/api/v1/alerts/{alert_id}/triage")
def update_alert_triage(
    alert_id: str,
    payload: AlertTriageUpdate,
    _: None = Depends(auth_dependency),
):
    updated = storage.update_alert_triage(
        alert_id=alert_id,
        triage_status=payload.status,
        triage_note=payload.note,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert = storage.get_alert(alert_id)
    return {
        "status": "ok",
        "alert": _alert_payload(alert) if alert else None,
    }


_DEFAULT_POLICY = {
    "policy_version": 1,
    "default_thresholds": {"medium": 0.6, "high": 0.85},
    "app_threshold_overrides": {},
    "export_enabled": True,
    "retention_days": 7,
    "detection_model": "ensemble_fusion",
    "shadow_model": None,
    "false_positive_budget_per_app_day": 12,
    "drift_high_threshold": 0.65,
    "capture_enabled": True,
    "theme_mode": "SYSTEM",
    "debug_mode_enabled": False,
    "fusion_weights": {
        "statistical": 0.28,
        "multivariate": 0.20,
        "sequence": 0.12,
        "linear": 0.16,
        "tflite": 0.12,
        "remote": 0.12,
        "beacon": 0.15,
        "drift": 0.10,
        "reputation": 0.18,
        "data_quality_penalty": 0.10,
        "response_anomaly": 0.82,
        "response_context": 0.18,
    },
    "disable_volume_features": False,
    "disable_timing_features": False,
    "disable_destination_features": False,
    "app_profile_overrides": {},
}

_GLOBAL_POLICY_ID = "__global__"


@app.get("/api/v1/policy/device/{device_id_pseudo}")
def get_device_policy(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    policy = storage.get_policy(device_id_pseudo) or storage.get_policy(_GLOBAL_POLICY_ID) or _DEFAULT_POLICY
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "policy": policy,
    }


@app.put("/api/v1/policy/device/{device_id_pseudo}")
def set_device_policy(
    device_id_pseudo: str,
    payload: DevicePolicyPayload,
    _: None = Depends(auth_dependency),
):
    policy = payload.model_dump(mode="json")
    storage.set_policy(device_id_pseudo=device_id_pseudo, policy=policy)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "policy": policy,
    }


@app.put("/api/v1/devices/{device_id_pseudo}/display-name")
def update_device_display_name(
    device_id_pseudo: str,
    payload: DeviceDisplayNameUpdate,
    _: None = Depends(auth_dependency),
):
    updated = storage.set_device_display_name(
        device_id_pseudo=device_id_pseudo,
        display_name=payload.display_name,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return {
        "status": "ok",
        **updated,
    }


@app.post("/api/v1/policy/apply")
def apply_policy_scope(
    payload: PolicyApplyScopeRequest,
    _: None = Depends(auth_dependency),
):
    policy = payload.policy.model_dump(mode="json")
    if payload.scope == "device":
        if not payload.device_ids:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_ids required for scope=device")
        target = payload.device_ids[0]
        storage.set_policy(device_id_pseudo=target, policy=policy)
        return {"status": "ok", "scope": "device", "applied": [target]}

    if payload.scope == "global_default":
        storage.set_policy(device_id_pseudo=_GLOBAL_POLICY_ID, policy=policy)
        return {"status": "ok", "scope": "global_default", "applied": [_GLOBAL_POLICY_ID]}

    if payload.scope == "selected_devices":
        if not payload.device_ids:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_ids required for scope=selected_devices")
        applied = []
        for target in payload.device_ids:
            storage.set_policy(device_id_pseudo=target, policy=policy)
            applied.append(target)
        return {"status": "ok", "scope": "selected_devices", "applied": applied}

    devices = storage.list_devices(limit=10_000)
    applied = []
    for item in devices:
        if item.device_id_pseudo == _GLOBAL_POLICY_ID:
            continue
        storage.set_policy(device_id_pseudo=item.device_id_pseudo, policy=policy)
        applied.append(item.device_id_pseudo)
    return {"status": "ok", "scope": "all_devices", "applied": applied}


@app.post("/api/v1/admin/purge")
def admin_purge(
    payload: AdminPurgeRequest,
    _: None = Depends(auth_dependency),
):
    counters = storage.purge_data(
        device_ids=payload.device_ids,
        clear_events=payload.clear_events,
        clear_alerts=payload.clear_alerts,
        clear_policies=payload.clear_policies,
        clear_models=payload.clear_models,
        clear_dead_letter=payload.clear_dead_letter,
        purge_test_data=payload.purge_test_data,
        all_devices=payload.all_devices,
    )
    return {
        "status": "ok",
        "result": counters,
        "queue": storage.stats(),
    }


@app.post("/api/v1/policy/device/{device_id_pseudo}/auto-tune")
def auto_tune_policy_from_feedback(
    device_id_pseudo: str,
    _: None = Depends(auth_dependency),
):
    current_policy = storage.get_policy(device_id_pseudo) or dict(_DEFAULT_POLICY)
    default_thresholds = current_policy.get("default_thresholds", {})
    base_medium = float(default_thresholds.get("medium", 0.6))
    base_high = float(default_thresholds.get("high", 0.85))

    overrides, feedback_stats = storage.feedback_adjust_policy(
        device_id_pseudo=device_id_pseudo,
        base_medium=base_medium,
        base_high=base_high,
    )

    merged_policy = dict(current_policy)
    merged_overrides = dict(merged_policy.get("app_threshold_overrides", {}))
    merged_overrides.update(overrides)
    merged_policy["app_threshold_overrides"] = merged_overrides
    merged_policy["policy_version"] = int(merged_policy.get("policy_version", 1)) + 1

    storage.set_policy(device_id_pseudo=device_id_pseudo, policy=merged_policy)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "feedback_stats": feedback_stats,
        "policy": merged_policy,
    }


@app.post("/api/v1/policy/simulate/{device_id_pseudo}")
def simulate_policy(
    device_id_pseudo: str,
    payload: PolicySimulationRequest,
    _: None = Depends(auth_dependency),
):
    simulation = storage.simulate_policy(
        device_id_pseudo=device_id_pseudo,
        policy=payload.policy.model_dump(mode="json"),
        limit=payload.limit,
    )
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "simulation": simulation,
    }


@app.get("/api/v1/retraining/samples/{device_id_pseudo}")
def export_retraining_samples(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=10, le=50000)] = 5000,
    _: None = Depends(auth_dependency),
):
    samples = storage.export_retraining_samples(device_id_pseudo=device_id_pseudo, limit=limit)
    return {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "samples": samples,
    }


@app.get("/api/v1/forensics/device/{device_id_pseudo}/bundle")
def export_forensics_bundle(
    device_id_pseudo: str,
    limit: Annotated[int, Query(ge=10, le=50000)] = 5000,
    _: None = Depends(auth_dependency),
):
    policy = storage.get_policy(device_id_pseudo) or dict(_DEFAULT_POLICY)
    alerts = storage.list_alerts(status=None, limit=limit, device_id_pseudo=device_id_pseudo)
    incidents = storage.list_incidents(limit=min(limit, 5000), device_id_pseudo=device_id_pseudo)
    quality = storage.quality_summary(device_id_pseudo=device_id_pseudo)
    payload = {
        "status": "ok",
        "device_id_pseudo": device_id_pseudo,
        "generated_epoch": int(time.time()),
        "policy": policy,
        "queue": storage.stats(),
        "quality": quality,
        "alerts": [_alert_payload(alert) for alert in alerts],
        "incidents": [_incident_payload(incident) for incident in incidents],
    }
    return payload
