"use client";

import { useMemo, useState } from "react";
import {
  createInitialMantaDemoState,
  MantaPhone,
  MantaDemoState,
  runDemoScenario,
} from "../components/MantaPhone";

type TraceStep = {
  time: string;
  stage: string;
  detail: string;
  tone: "neutral" | "good" | "warn";
};

const initialTrace: TraceStep[] = [
  { time: "18:42:04", stage: "Packet metadata", detail: "TCP · outbound · 1,248 B · payload skipped", tone: "neutral" },
  { time: "18:42:05", stage: "Flow attribution", detail: "org.telegram.messenger · destination hash 7b4…e91", tone: "neutral" },
  { time: "18:42:06", stage: "Feature window", detail: "burst rate ↑ · destination novelty 0.91", tone: "warn" },
  { time: "18:42:06", stage: "Local inference", detail: "Android RF · anomaly score 0.82", tone: "warn" },
  { time: "18:42:07", stage: "Privacy export", detail: "Medium · app and endpoint identifiers hashed", tone: "good" },
];

type ScenarioId = "normal" | "burst" | "beacon" | "policy" | "reset";

const scenarios: Array<{ id: ScenarioId; title: string; body: string }> = [
  {
    id: "normal",
    title: "Normal browsing",
    body: "Adds a clean traffic window and shows why no alert is raised.",
  },
  {
    id: "burst",
    title: "Suspicious burst",
    body: "Creates a high-confidence Telegram alert from novelty and volume.",
  },
  {
    id: "beacon",
    title: "Beacon pattern",
    body: "Creates a periodic-flow alert for an unknown UID.",
  },
  {
    id: "policy",
    title: "Sync policy",
    body: "Flushes the export queue and updates backend-assisted policy state.",
  },
  {
    id: "reset",
    title: "Reset demo",
    body: "Restores the initial app, alert and trace state.",
  },
];

function now() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

export default function DemoPage() {
  const [trace, setTrace] = useState(initialTrace);
  const [demoState, setDemoState] = useState<MantaDemoState>(createInitialMantaDemoState);
  const [token, setToken] = useState("");
  const [backendStatus, setBackendStatus] = useState("Public simulation");
  const [isRefreshing, setIsRefreshing] = useState(false);

  const traceSummary = useMemo(() => {
    const alerts = trace.filter((item) => item.tone === "warn").length;
    return `${trace.length} stages · ${alerts} elevated signals · 0 payload reads`;
  }, [trace]);

  function addActivity(detail: string) {
    const activity: TraceStep = {
      time: now(),
      stage: "App interaction",
      detail,
      tone: "good",
    };
    setTrace((current) => [
      activity,
      ...current,
    ].slice(0, 9));
  }

  function runScenario(scenario: ScenarioId) {
    if (scenario === "reset") {
      setDemoState(runDemoScenario(demoState, scenario));
      setTrace(initialTrace);
      setBackendStatus("Public simulation");
      return;
    }

    setDemoState((current) => runDemoScenario(current, scenario));
    setTrace((current) => [...traceForScenario(scenario, demoState), ...current].slice(0, 9));
  }

  async function refreshBackend() {
    const cleanToken = token.trim();
    if (!cleanToken) {
      setBackendStatus("Enter the private adapter token first");
      return;
    }

    try {
      setIsRefreshing(true);
      setBackendStatus("Connecting");
      const headers = { Authorization: `Bearer ${cleanToken}` };
      const [healthResponse, alertsResponse] = await Promise.all([
        fetch("/health", { headers }),
        fetch("/api/v1/alerts?limit=3", { headers }),
      ]);
      if (!healthResponse.ok) throw new Error(`health returned ${healthResponse.status}`);
      if (!alertsResponse.ok) throw new Error(`alerts returned ${alertsResponse.status}`);

      const health = await healthResponse.json();
      const payload = await alertsResponse.json();
      const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
      setBackendStatus(`Connected · ${health?.queue?.pending ?? 0} queued · ${alerts.length} recent alerts`);
      const backendStep: TraceStep = {
        time: now(),
        stage: "Server backend",
        detail: alerts.length ? `Loaded ${alerts.length} authenticated alerts` : "Connected; no stored alerts yet",
        tone: "good",
      };
      setDemoState((current) => ({ ...current, backendConnected: true, exportQueue: health?.queue?.pending ?? current.exportQueue }));
      setTrace((current) => [
        backendStep,
        ...current,
      ].slice(0, 9));
    } catch (error) {
      setBackendStatus(error instanceof Error ? `Unavailable · ${error.message}` : "Backend unavailable");
    } finally {
      setIsRefreshing(false);
    }
  }

  return (
    <>
      <section className="demo-intro container">
        <div>
          <p className="eyebrow">Interactive system demo</p>
          <h1>Use the app, then follow the decision.</h1>
        </div>
        <p>
          This is a stateful browser reconstruction of the Android information architecture. It exposes the
          protection, app inventory, alert-triage, privacy, model and export flows without requiring VPN permission.
        </p>
      </section>

      <section className="demo-workbench container">
        <div className="demo-phone-stage">
          <div className="stage-label">
            <span>Android endpoint</span>
            <b>Interactive</b>
          </div>
          <MantaPhone state={demoState} onStateChange={setDemoState} onActivity={addActivity} />
        </div>

        <div className="demo-observer">
          <div className="observer-heading">
            <div>
              <span>Decision trace</span>
              <h2>What happened to the traffic window</h2>
            </div>
          </div>

          <div className="scenario-grid" aria-label="Demo scenarios">
            {scenarios.map((scenario) => (
              <button type="button" key={scenario.id} onClick={() => runScenario(scenario.id)}>
                <strong>{scenario.title}</strong>
                <span>{scenario.body}</span>
              </button>
            ))}
          </div>

          <div className="trace-summary">
            <span className="live-pulse" />
            <strong>{traceSummary}</strong>
          </div>

          <div className="trace-list" aria-live="polite">
            {trace.map((item, index) => (
              <article className={`trace-row trace-${item.tone}`} key={`${item.time}-${item.stage}-${index}`}>
                <time>{item.time}</time>
                <span className="trace-node" />
                <div>
                  <strong>{item.stage}</strong>
                  <p>{item.detail}</p>
                </div>
              </article>
            ))}
          </div>

          <details className="backend-panel">
            <summary>
              <span>Optional authenticated server data</span>
              <b>{backendStatus}</b>
            </summary>
            <div>
              <p>
                The token stays in this page state and is sent only to the same-origin server endpoint.
              </p>
              <label htmlFor="adapter-token">Adapter token</label>
              <div className="backend-input-row">
                <input
                  id="adapter-token"
                  type="password"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  placeholder="Private server token"
                  autoComplete="off"
                />
                <button type="button" onClick={refreshBackend} disabled={isRefreshing}>
                  {isRefreshing ? "Loading" : "Connect"}
                </button>
              </div>
            </div>
          </details>
        </div>
      </section>

      <section className="container demo-explainer">
        <article>
          <span>Captured</span>
          <h3>Flow metadata</h3>
          <p>Direction, duration, byte and packet counts, timing, protocol and destination-derived features.</p>
        </article>
        <article>
          <span>Never captured</span>
          <h3>Payload content</h3>
          <p>Messages, passwords, images, files and application-layer bodies are outside the detection path.</p>
        </article>
        <article>
          <span>Explicit limitation</span>
          <h3>Traffic analysis remains</h3>
          <p>Encryption and reduced export do not hide timing and volume patterns from the network observer.</p>
        </article>
      </section>
    </>
  );
}

function traceForScenario(scenario: Exclude<ScenarioId, "reset">, state: MantaDemoState): TraceStep[] {
  const privacy = `${state.privacy} privacy`;
  const exportDetail = state.exportEnabled
    ? `${privacy} · telemetry queued for same-origin server endpoint`
    : `${privacy} · export disabled, local-only decision`;

  if (scenario === "normal") {
    return [
      { time: now(), stage: "Packet metadata", detail: "TCP/UDP · browser window · payload skipped", tone: "neutral" },
      { time: now(), stage: "Flow attribution", detail: "com.android.chrome · known app profile", tone: "neutral" },
      { time: now(), stage: "Feature window", detail: "60 s window updated · DNS/web ratios within baseline", tone: "neutral" },
      { time: now(), stage: "Local inference", detail: `${state.detectionModel} · score 0.29 · below alert threshold`, tone: "good" },
      { time: now(), stage: "Privacy export", detail: exportDetail, tone: state.exportEnabled ? "good" : "neutral" },
    ];
  }

  if (scenario === "burst") {
    return [
      { time: now(), stage: "Packet metadata", detail: "TCP · outbound burst · packet payload skipped", tone: "neutral" },
      { time: now(), stage: "Flow attribution", detail: "org.telegram.messenger · destination hash 7b4...e91", tone: "neutral" },
      { time: now(), stage: "Feature window", detail: "destination novelty 0.93 · outbound byte spike 0.81", tone: "warn" },
      { time: now(), stage: "Local inference", detail: `${state.detectionModel} · anomaly score 0.86`, tone: "warn" },
      { time: now(), stage: "Alert triage", detail: "High-severity alert opened with evidence bars and analyst feedback actions", tone: "warn" },
      { time: now(), stage: "Privacy export", detail: exportDetail, tone: state.exportEnabled ? "good" : "neutral" },
    ];
  }

  if (scenario === "beacon") {
    return [
      { time: now(), stage: "Packet metadata", detail: "Repeated short flows · stable timing · payload skipped", tone: "neutral" },
      { time: now(), stage: "Flow attribution", detail: "uid.10284 · installed app name unavailable", tone: "neutral" },
      { time: now(), stage: "Feature window", detail: "periodicity 0.87 · small-flow ratio 0.76", tone: "warn" },
      { time: now(), stage: "Local inference", detail: `${state.detectionModel} · anomaly score 0.88`, tone: "warn" },
      { time: now(), stage: "Alert triage", detail: "Unknown UID moved to Needs review in the app inventory", tone: "warn" },
      { time: now(), stage: "Privacy export", detail: exportDetail, tone: state.exportEnabled ? "good" : "neutral" },
    ];
  }

  return [
    { time: now(), stage: "Server backend", detail: "Authenticated policy sync completed", tone: "good" },
    { time: now(), stage: "Remote policy", detail: "Thresholds and privacy export policy are current", tone: "good" },
    { time: now(), stage: "Export queue", detail: "0 pending · 0 dead-letter", tone: "good" },
  ];
}
