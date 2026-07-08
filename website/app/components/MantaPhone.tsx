"use client";

import { useState } from "react";

export type PhoneTab = "home" | "apps" | "alerts" | "settings";
export type PrivacyMode = "Low" | "Medium" | "Strict";
export type DetectionModel = "Android RF" | "Statistical" | "Sequence";
export type AlertSeverity = "High" | "Medium" | "Low";
export type TriageStatus = "open" | "dangerous" | "false-positive" | "dismissed";

export type MantaDemoAlert = {
  id: string;
  appId: string;
  appName: string;
  packageName: string;
  title: string;
  summary: string;
  severity: AlertSeverity;
  score: number;
  model: DetectionModel;
  shadowModel?: DetectionModel;
  destination: string;
  observed: string;
  status: TriageStatus;
  evidence: Array<{ label: string; value: number; tone: "red" | "amber" | "teal" }>;
};

export type MantaDemoApp = {
  id: string;
  name: string;
  packageName: string;
  baseFlows: number;
  baseline: string;
  profile: string;
  isSystem?: boolean;
};

export type MantaDemoState = {
  tab: PhoneTab;
  consentAccepted: boolean;
  protectionActive: boolean;
  privacy: PrivacyMode;
  exportEnabled: boolean;
  backendConnected: boolean;
  diagnosticsEnabled: boolean;
  flowCount: number;
  exportQueue: number;
  detectionModel: DetectionModel;
  shadowModelEnabled: boolean;
  appFilter: "all" | "review" | "normal";
  alertFilter: "all" | AlertSeverity;
  selectedAppId: string | null;
  alerts: MantaDemoAlert[];
  apps: MantaDemoApp[];
};

type MantaPhoneProps = {
  autoPlay?: boolean;
  compact?: boolean;
  state?: MantaDemoState;
  onStateChange?: (state: MantaDemoState) => void;
  onActivity?: (message: string) => void;
};

const tabs: Array<{ id: PhoneTab; label: string; icon: string }> = [
  { id: "home", label: "Home", icon: "⌂" },
  { id: "apps", label: "Apps", icon: "▦" },
  { id: "alerts", label: "Alerts", icon: "!" },
  { id: "settings", label: "Settings", icon: "···" },
];

const appFilters: Array<{ id: MantaDemoState["appFilter"]; label: string }> = [
  { id: "all", label: "All" },
  { id: "review", label: "Needs review" },
  { id: "normal", label: "Normal" },
];

const alertFilters: Array<{ id: MantaDemoState["alertFilter"]; label: string }> = [
  { id: "all", label: "All" },
  { id: "High", label: "High" },
  { id: "Medium", label: "Medium" },
  { id: "Low", label: "Low" },
];

const modelOptions: DetectionModel[] = ["Android RF", "Statistical", "Sequence"];

export function createInitialMantaDemoState(): MantaDemoState {
  return {
    tab: "home",
    consentAccepted: true,
    protectionActive: true,
    privacy: "Medium",
    exportEnabled: true,
    backendConnected: true,
    diagnosticsEnabled: false,
    flowCount: 1284,
    exportQueue: 0,
    detectionModel: "Android RF",
    shadowModelEnabled: true,
    appFilter: "all",
    alertFilter: "all",
    selectedAppId: null,
    apps: [
      {
        id: "telegram",
        name: "Telegram",
        packageName: "org.telegram.messenger",
        baseFlows: 326,
        baseline: "baseline drifting",
        profile: "Messaging",
      },
      {
        id: "chrome",
        name: "Chrome",
        packageName: "com.android.chrome",
        baseFlows: 428,
        baseline: "baseline stable",
        profile: "Browser",
      },
      {
        id: "maps",
        name: "Google Maps",
        packageName: "com.google.android.apps.maps",
        baseFlows: 91,
        baseline: "baseline stable",
        profile: "Navigation",
      },
      {
        id: "unknown-uid",
        name: "Unknown UID 10284",
        packageName: "uid.10284",
        baseFlows: 18,
        baseline: "new destination family",
        profile: "Unknown",
      },
    ],
    alerts: [
      {
        id: "telegram-burst",
        appId: "telegram",
        appName: "Telegram",
        packageName: "org.telegram.messenger",
        title: "Rare destination during outbound burst",
        summary:
          "A rare destination appeared during a sharp outbound burst. The score combines local model output, periodicity and destination novelty.",
        severity: "High",
        score: 82,
        model: "Android RF",
        shadowModel: "Sequence",
        destination: "destination hash 7b4...e91",
        observed: "18:42",
        status: "open",
        evidence: [
          { label: "Destination novelty", value: 91, tone: "red" },
          { label: "Outbound byte spike", value: 78, tone: "amber" },
          { label: "Periodic beacon score", value: 64, tone: "teal" },
        ],
      },
      {
        id: "chrome-baseline",
        appId: "chrome",
        appName: "Chrome",
        packageName: "com.android.chrome",
        title: "Short DNS-heavy browsing window",
        summary:
          "The feature window is above the app median but still within the learned browser profile after stability checks.",
        severity: "Low",
        score: 34,
        model: "Statistical",
        shadowModel: "Sequence",
        destination: "common browser destinations",
        observed: "18:39",
        status: "dismissed",
        evidence: [
          { label: "DNS flow ratio", value: 42, tone: "teal" },
          { label: "Byte variance", value: 31, tone: "teal" },
          { label: "Baseline drift", value: 22, tone: "teal" },
        ],
      },
    ],
  };
}

export function runDemoScenario(state: MantaDemoState, scenario: "normal" | "burst" | "beacon" | "policy" | "reset"): MantaDemoState {
  if (scenario === "reset") {
    return createInitialMantaDemoState();
  }

  if (scenario === "normal") {
    return {
      ...state,
      tab: "home",
      flowCount: state.flowCount + 24,
      exportQueue: state.exportEnabled ? state.exportQueue + 1 : state.exportQueue,
      alerts: state.alerts.map((alert) =>
        alert.id === "chrome-baseline"
          ? { ...alert, status: "dismissed", score: 29, observed: currentMinuteLabel() }
          : alert,
      ),
    };
  }

  if (scenario === "policy") {
    return {
      ...state,
      tab: "settings",
      backendConnected: true,
      exportQueue: 0,
      privacy: state.privacy === "Low" ? "Medium" : state.privacy,
    };
  }

  const suspiciousAlert: MantaDemoAlert =
    scenario === "beacon"
      ? {
          id: "unknown-beacon",
          appId: "unknown-uid",
          appName: "Unknown UID 10284",
          packageName: "uid.10284",
          title: "Periodic beacon-like flow pattern",
          summary:
            "Repeated short flows reached a new destination family with unusually stable timing. The alert is raised without inspecting payload bytes.",
          severity: "High",
          score: 88,
          model: state.detectionModel,
          shadowModel: state.shadowModelEnabled ? "Sequence" : undefined,
          destination: "new destination family",
          observed: currentMinuteLabel(),
          status: "open",
          evidence: [
            { label: "Periodicity", value: 87, tone: "red" },
            { label: "Destination novelty", value: 82, tone: "amber" },
            { label: "Small-flow ratio", value: 76, tone: "amber" },
          ],
        }
      : {
          id: "telegram-burst",
          appId: "telegram",
          appName: "Telegram",
          packageName: "org.telegram.messenger",
          title: "Rare destination during outbound burst",
          summary:
            "A rare destination appeared during a sharp outbound burst. The score combines local model output, periodicity and destination novelty.",
          severity: "High",
          score: 86,
          model: state.detectionModel,
          shadowModel: state.shadowModelEnabled ? "Sequence" : undefined,
          destination: "destination hash 7b4...e91",
          observed: currentMinuteLabel(),
          status: "open",
          evidence: [
            { label: "Destination novelty", value: 93, tone: "red" },
            { label: "Outbound byte spike", value: 81, tone: "amber" },
            { label: "Baseline drift", value: 69, tone: "teal" },
          ],
        };

  const existing = state.alerts.some((alert) => alert.id === suspiciousAlert.id);

  return {
    ...state,
    tab: "alerts",
    flowCount: state.flowCount + (scenario === "beacon" ? 36 : 57),
    exportQueue: state.exportEnabled ? state.exportQueue + 1 : state.exportQueue,
    alertFilter: "all",
    selectedAppId: suspiciousAlert.appId,
    alerts: existing
      ? state.alerts.map((alert) => (alert.id === suspiciousAlert.id ? suspiciousAlert : alert))
      : [suspiciousAlert, ...state.alerts],
  };
}

export function MantaPhone({ compact = false, state: controlledState, onStateChange, onActivity }: MantaPhoneProps) {
  const [localState, setLocalState] = useState(createInitialMantaDemoState);
  const state = controlledState ?? localState;

  function updateState(next: MantaDemoState | ((current: MantaDemoState) => MantaDemoState), activity?: string) {
    const resolved = typeof next === "function" ? next(state) : next;
    if (!controlledState) {
      setLocalState(resolved);
    }
    onStateChange?.(resolved);
    if (activity) onActivity?.(activity);
  }

  function patchState(patch: Partial<MantaDemoState>, activity?: string) {
    updateState({ ...state, ...patch }, activity);
  }

  function selectTab(next: PhoneTab) {
    patchState({ tab: next, selectedAppId: next === "apps" ? state.selectedAppId : state.selectedAppId }, `Opened ${next}`);
  }

  function toggleProtection() {
    patchState(
      { protectionActive: !state.protectionActive, consentAccepted: true },
      state.protectionActive ? "Paused metadata-only VPN capture" : "Started metadata-only VPN capture",
    );
  }

  function setAlertStatus(alertId: string, status: TriageStatus, label: string) {
    updateState(
      {
        ...state,
        alerts: state.alerts.map((alert) => (alert.id === alertId ? { ...alert, status } : alert)),
      },
      `${label}: feedback saved for local review and retraining`,
    );
  }

  const openAlerts = state.alerts.filter((alert) => alert.status === "open");
  const primaryAlert = openAlerts[0] ?? state.alerts[0];
  const apps = buildAppRows(state);
  const filteredApps = apps.filter((app) => {
    if (state.appFilter === "review") return app.openAlertCount > 0;
    if (state.appFilter === "normal") return app.openAlertCount === 0;
    return true;
  });
  const filteredAlerts = state.alerts.filter((alert) => state.alertFilter === "all" || alert.severity === state.alertFilter);
  const selectedApp = apps.find((app) => app.id === state.selectedAppId) ?? null;

  return (
    <div className={`phone-device${compact ? " phone-compact" : ""}`} aria-label="Interactive MANTA Android app">
      <div className="phone-hardware">
        <span />
        <i />
      </div>

      <div className="phone-appbar">
        <img src="/elephant-logo.png" alt="" />
        <div>
          <strong>MANTA</strong>
          <span>{screenSubtitle(state)}</span>
        </div>
        <b className={state.protectionActive ? "online-dot" : "paused-dot"} aria-label={state.protectionActive ? "Protection active" : "Protection paused"} />
      </div>

      <div className="phone-viewport" aria-live="polite">
        {state.tab === "home" && (
          <div className="phone-screen-content">
            <section className="protection-card">
              <div className="phone-status-line">
                <span className={state.protectionActive ? "status-active" : "status-paused"}>
                  <i />
                  {state.protectionActive ? "Protection active" : "Protection paused"}
                </span>
                <span className="shield-mark">◇</span>
              </div>
              <h3>{state.protectionActive ? "Monitoring network behaviour" : "Capture is currently paused"}</h3>
              <p>
                MANTA scores encrypted traffic from timing, volume, protocol and destination-derived metadata.
                Packet payloads are never inspected.
              </p>
              {!state.consentAccepted && <p className="phone-warning">Consent is required before capture can start.</p>}
              <button type="button" onClick={toggleProtection}>
                {state.protectionActive ? "Pause capture" : "Start protected capture"}
              </button>
            </section>

            <div className="phone-metrics">
              <div><strong>{state.flowCount.toLocaleString()}</strong><span>flows today</span></div>
              <div><strong>{openAlerts.length}</strong><span>open alerts</span></div>
              <div><strong>0</strong><span>payloads read</span></div>
            </div>

            <div className="phone-section-title">
              <div>
                <strong>Needs attention</strong>
                <span>{openAlerts.length ? "One high-confidence pattern" : "No open high-risk alerts"}</span>
              </div>
              <button type="button" onClick={() => selectTab("alerts")}>Open</button>
            </div>

            {primaryAlert ? (
              <button className={`attention-row severity-${primaryAlert.severity.toLowerCase()}`} type="button" onClick={() => selectTab("alerts")}>
                <span className="risk-score">{primaryAlert.score}</span>
                <span><strong>{primaryAlert.appName}</strong><small>{primaryAlert.title}</small></span>
                <b>{primaryAlert.status === "open" ? "Review" : "Reviewed"}</b>
              </button>
            ) : (
              <div className="empty-phone-state">No alerts have been generated in this simulation.</div>
            )}

            <div className="runtime-card">
              <strong>Runtime status</strong>
              <PhoneStatus label="On-device model" detail={`${state.detectionModel} · balanced`} state="Ready" tone="good" />
              <PhoneStatus label="Shadow model" detail="Sequence comparison" state={state.shadowModelEnabled ? "On" : "Off"} tone={state.shadowModelEnabled ? "good" : "muted"} />
              <PhoneStatus label="Server backend" detail={state.backendConnected ? "Last sync 14 seconds ago" : "Same-origin endpoint unavailable"} state={state.backendConnected ? "Online" : "Offline"} tone={state.backendConnected ? "good" : "warn"} />
              <PhoneStatus label="Export queue" detail={`${state.exportQueue} pending · 0 dead-letter`} state={state.exportEnabled ? "On" : "Off"} tone={state.exportQueue > 0 ? "warn" : "good"} />
            </div>
          </div>
        )}

        {state.tab === "apps" && (
          <div className="phone-screen-content">
            {selectedApp ? (
              <AppDetail
                app={selectedApp}
                alerts={state.alerts.filter((alert) => alert.appId === selectedApp.id)}
                onBack={() => patchState({ selectedAppId: null }, "Returned to app inventory")}
                onOpenAlerts={() => patchState({ tab: "alerts", selectedAppId: selectedApp.id }, `Opened alerts for ${selectedApp.name}`)}
              />
            ) : (
              <>
                <PhoneIntro title="App activity" body="Per-app baselines, alert history and tuning profiles." />
                <div className="phone-filter-row">
                  {appFilters.map((filter) => (
                    <button
                      className={state.appFilter === filter.id ? "selected" : ""}
                      type="button"
                      key={filter.id}
                      onClick={() => patchState({ appFilter: filter.id }, `Filtered apps by ${filter.label}`)}
                    >
                      {filter.label}
                    </button>
                  ))}
                </div>
                <button className="scan-row" type="button" onClick={() => patchState({ flowCount: state.flowCount + 3 }, "Scanned installed app catalogue")}>
                  <span>Scan installed apps</span>
                  <b>{filteredApps.length} apps in view</b>
                </button>
                {filteredApps.map((app) => (
                  <button
                    className="phone-app-row"
                    key={app.id}
                    type="button"
                    onClick={() => patchState({ selectedAppId: app.id }, `Opened ${app.name} profile`)}
                  >
                    <span className={`app-monogram ${app.openAlertCount ? "review" : "normal"}`}>{app.name[0]}</span>
                    <div>
                      <strong>{app.name}</strong>
                      <small>{app.packageName}</small>
                      <span>{app.flows.toLocaleString()} flows · {app.baseline}</span>
                    </div>
                    <b className={app.openAlertCount ? "review" : "normal"}>{app.openAlertCount ? "Review" : "Normal"}</b>
                  </button>
                ))}
              </>
            )}
          </div>
        )}

        {state.tab === "alerts" && (
          <div className="phone-screen-content">
            <PhoneIntro title="Alert triage" body="Filter, inspect evidence and feed analyst labels back into the system." />
            <div className="phone-filter-row">
              {alertFilters.map((filter) => (
                <button
                  className={state.alertFilter === filter.id ? "selected" : ""}
                  type="button"
                  key={filter.id}
                  onClick={() => patchState({ alertFilter: filter.id }, `Filtered alerts by ${filter.label}`)}
                >
                  {filter.label}
                </button>
              ))}
            </div>
            <div className="compact-toggle-row">
              <span>Repeated-alert compaction</span>
              <b>On</b>
            </div>
            {filteredAlerts.length ? (
              filteredAlerts.map((alert) => (
                <article className={`phone-alert-card${alert.status !== "open" ? " resolved" : ""}`} key={alert.id}>
                  <div className="phone-alert-heading">
                    <div>
                      <strong>{alert.appName}</strong>
                      <em>{alert.title}</em>
                      <span>{alert.severity} confidence · score {(alert.score / 100).toFixed(2)}</span>
                    </div>
                    <b>{triageLabel(alert.status)}</b>
                  </div>
                  <p>{alert.summary}</p>
                  <div className="alert-model-row">
                    <span>{alert.model}</span>
                    <span>{alert.shadowModel ? `Shadow: ${alert.shadowModel}` : "No shadow model"}</span>
                  </div>
                  {alert.evidence.map((item) => (
                    <Signal label={item.label} value={item.value} tone={item.tone} key={item.label} />
                  ))}
                  <small>Observed {alert.observed} · {alert.destination} · No packet payload captured</small>
                  {alert.status === "open" ? (
                    <div className="phone-alert-actions three-actions">
                      <button type="button" onClick={() => setAlertStatus(alert.id, "dangerous", "Marked dangerous")}>Dangerous</button>
                      <button type="button" onClick={() => setAlertStatus(alert.id, "false-positive", "Marked false positive")}>False positive</button>
                      <button type="button" onClick={() => setAlertStatus(alert.id, "dismissed", "Dismissed neutral")}>Dismiss</button>
                    </div>
                  ) : (
                    <div className="feedback-saved">Feedback saved: {triageLabel(alert.status).toLowerCase()}</div>
                  )}
                </article>
              ))
            ) : (
              <div className="empty-phone-state">No alerts match the selected filter.</div>
            )}
          </div>
        )}

        {state.tab === "settings" && (
          <div className="phone-screen-content">
            <PhoneIntro title="Privacy, models and export" body="Control what leaves the device and how anomaly decisions are made." />
            <section className="privacy-card">
              <span>Privacy mode</span>
              <h3>{state.privacy}</h3>
              <p>{privacyCopy(state.privacy)}</p>
              <div className="privacy-options">
                {(["Low", "Medium", "Strict"] as const).map((level) => (
                  <button
                    className={state.privacy === level ? "selected" : ""}
                    type="button"
                    key={level}
                    onClick={() => patchState({ privacy: level }, `Changed privacy mode to ${level}`)}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </section>
            <section className="runtime-card">
              <strong>Detection model</strong>
              <div className="model-options">
                {modelOptions.map((model) => (
                  <button
                    className={state.detectionModel === model ? "selected" : ""}
                    type="button"
                    key={model}
                    onClick={() => patchState({ detectionModel: model }, `Selected ${model} detector`)}
                  >
                    {model}
                  </button>
                ))}
              </div>
              <ToggleRow
                label="Shadow model"
                detail="Compare sequence score without making it the primary decision"
                enabled={state.shadowModelEnabled}
                onClick={() => patchState({ shadowModelEnabled: !state.shadowModelEnabled }, state.shadowModelEnabled ? "Disabled shadow model" : "Enabled shadow model")}
              />
              <ToggleRow
                label="Privacy export"
                detail={`${state.exportQueue} pending · same-origin server endpoint`}
                enabled={state.exportEnabled}
                onClick={() => patchState({ exportEnabled: !state.exportEnabled }, state.exportEnabled ? "Disabled privacy export" : "Enabled privacy export")}
              />
              <ToggleRow
                label="Diagnostics mode"
                detail="Shows extra local validation details while testing"
                enabled={state.diagnosticsEnabled}
                onClick={() => patchState({ diagnosticsEnabled: !state.diagnosticsEnabled }, state.diagnosticsEnabled ? "Disabled diagnostics mode" : "Enabled diagnostics mode")}
              />
            </section>
            <div className="runtime-card">
              <strong>Backend and queue</strong>
              <PhoneStatus label="Server endpoint" detail="bachelor.elfeel.me" state={state.backendConnected ? "Connected" : "Disconnected"} tone={state.backendConnected ? "good" : "warn"} />
              <PhoneStatus label="Policy sync" detail={state.backendConnected ? "Remote thresholds current" : "Using local defaults"} state={state.backendConnected ? "Synced" : "Local"} tone={state.backendConnected ? "good" : "warn"} />
              <PhoneStatus label="Export queue" detail={`${state.exportQueue} pending · 0 dead-letter`} state={state.exportQueue ? "Pending" : "Clear"} tone={state.exportQueue ? "warn" : "good"} />
              <div className="settings-actions">
                <button type="button" onClick={() => patchState({ backendConnected: true, exportQueue: 0 }, "Synced policy and flushed export queue")}>Sync policy</button>
                <button type="button" onClick={() => patchState({ backendConnected: !state.backendConnected }, state.backendConnected ? "Simulated backend disconnect" : "Simulated backend reconnect")}>
                  {state.backendConnected ? "Disconnect" : "Reconnect"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <nav className="phone-nav" aria-label="App navigation">
        {tabs.map((item) => (
          <button
            type="button"
            className={state.tab === item.id ? "selected" : ""}
            onClick={() => selectTab(item.id)}
            key={item.id}
            aria-label={`Open ${item.label}`}
          >
            <span>{item.icon}</span>
            <small>{item.label}</small>
          </button>
        ))}
      </nav>
    </div>
  );
}

function buildAppRows(state: MantaDemoState) {
  return state.apps.map((app) => {
    const appAlerts = state.alerts.filter((alert) => alert.appId === app.id);
    const openAlertCount = appAlerts.filter((alert) => alert.status === "open").length;
    const highest = appAlerts.find((alert) => alert.status === "open") ?? appAlerts[0];
    return {
      ...app,
      flows: app.baseFlows + (app.id === "telegram" ? Math.floor((state.flowCount - 1284) * 0.38) : app.id === "unknown-uid" ? Math.floor((state.flowCount - 1284) * 0.12) : 0),
      openAlertCount,
      alertCount: appAlerts.length,
      highestSeverity: highest?.severity,
      lastAlert: highest?.observed,
    };
  });
}

function AppDetail({
  app,
  alerts,
  onBack,
  onOpenAlerts,
}: {
  app: ReturnType<typeof buildAppRows>[number];
  alerts: MantaDemoAlert[];
  onBack: () => void;
  onOpenAlerts: () => void;
}) {
  const open = alerts.filter((alert) => alert.status === "open").length;
  return (
    <>
      <button className="back-row" type="button" onClick={onBack}>Back to app inventory</button>
      <section className="app-detail-card">
        <span className={`app-monogram ${open ? "review" : "normal"}`}>{app.name[0]}</span>
        <div>
          <h3>{app.name}</h3>
          <p>{app.packageName}</p>
        </div>
        <div className="app-detail-chips">
          <span>{app.isSystem ? "System" : "User"}</span>
          <span>{app.profile}</span>
          <span>{alerts.length} alerts</span>
          <span>{open} open</span>
        </div>
      </section>
      <section className="runtime-card">
        <strong>Per-app tuning</strong>
        <PhoneStatus label="Profile" detail={app.profile} state="Active" tone="good" />
        <PhoneStatus label="Thresholds" detail="0.35 low · 0.55 medium · 0.75 high" state="Default" tone="good" />
        <PhoneStatus label="Baseline" detail={app.baseline} state={open ? "Review" : "Stable"} tone={open ? "warn" : "good"} />
      </section>
      <button className="app-open-alerts" type="button" onClick={onOpenAlerts}>
        Open alerts for this app
      </button>
    </>
  );
}

function PhoneIntro({ title, body }: { title: string; body: string }) {
  return <div className="phone-intro"><h3>{title}</h3><p>{body}</p></div>;
}

function PhoneStatus({ label, detail, state, tone = "good" }: { label: string; detail: string; state: string; tone?: "good" | "warn" | "muted" }) {
  return (
    <div className={`phone-runtime-row runtime-${tone}`}>
      <i />
      <span><strong>{label}</strong><small>{detail}</small></span>
      <b>{state}</b>
    </div>
  );
}

function Signal({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="signal">
      <span><small>{label}</small><b>{value}%</b></span>
      <i><b className={tone} style={{ width: `${value}%` }} /></i>
    </div>
  );
}

function ToggleRow({ label, detail, enabled, onClick }: { label: string; detail: string; enabled: boolean; onClick: () => void }) {
  return (
    <button className="toggle-row" type="button" onClick={onClick}>
      <span><strong>{label}</strong><small>{detail}</small></span>
      <b className={enabled ? "enabled" : ""}>{enabled ? "On" : "Off"}</b>
    </button>
  );
}

function screenSubtitle(state: MantaDemoState) {
  if (state.tab === "apps") return state.selectedAppId ? "Per-app tuning profile" : "App baselines and inventory";
  if (state.tab === "alerts") return `${state.alerts.filter((alert) => alert.status === "open").length} open alerts`;
  if (state.tab === "settings") return `${state.detectionModel} · ${state.privacy} privacy`;
  return "Metadata-only endpoint monitor";
}

function privacyCopy(privacy: PrivacyMode) {
  if (privacy === "Strict") return "Only reduced feature windows are exported. Endpoint context is removed before leaving the device.";
  if (privacy === "Low") return "Readable app and selected site context remains; raw network addresses are hashed.";
  return "App and destination identifiers are hashed while timing, count and protocol features remain useful.";
}

function triageLabel(status: TriageStatus) {
  if (status === "false-positive") return "False positive";
  if (status === "dangerous") return "Dangerous";
  if (status === "dismissed") return "Dismissed";
  return "Open";
}

function currentMinuteLabel() {
  return new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
}
