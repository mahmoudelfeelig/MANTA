"use client";

import { useMemo, useState } from "react";
import { MantaPhone } from "../components/MantaPhone";

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

function now() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

export default function DemoPage() {
  const [trace, setTrace] = useState(initialTrace);
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

  function simulateWindow() {
    const sequence: TraceStep[] = [
      { time: now(), stage: "Packet metadata", detail: "UDP · inbound/outbound · payload skipped", tone: "neutral" },
      { time: now(), stage: "Feature window", detail: "60 s window updated · 24 behavioural features", tone: "neutral" },
      { time: now(), stage: "Local inference", detail: "Score 0.27 · within app baseline", tone: "good" },
    ];
    setTrace((current) => [...sequence, ...current].slice(0, 9));
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
          This is a faithful browser reconstruction of the Android information architecture. It exposes the
          real protection, app inventory, alert-triage and privacy flows without requiring VPN permission.
        </p>
      </section>

      <section className="demo-workbench container">
        <div className="demo-phone-stage">
          <div className="stage-label">
            <span>Android endpoint</span>
            <b>Interactive</b>
          </div>
          <MantaPhone onActivity={addActivity} />
        </div>

        <div className="demo-observer">
          <div className="observer-heading">
            <div>
              <span>Decision trace</span>
              <h2>What happened to the traffic window</h2>
            </div>
            <button className="button button-dark" type="button" onClick={simulateWindow}>
              Generate normal window
            </button>
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
