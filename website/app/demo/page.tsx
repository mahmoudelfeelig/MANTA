"use client";

import { useEffect, useMemo, useState } from "react";

type DemoEvent = {
  id: string;
  app: string;
  destination: string;
  score: number;
  severity: "low" | "medium" | "high";
  status: string;
  features: string[];
};

const seedEvents: DemoEvent[] = [
  {
    id: "evt-1042",
    app: "com.android.chrome",
    destination: "cdn.example.net",
    score: 0.18,
    severity: "low",
    status: "normal",
    features: ["duration", "bytes_out", "dst_port"],
  },
  {
    id: "evt-1043",
    app: "org.telegram.messenger",
    destination: "api.service.example",
    score: 0.41,
    severity: "medium",
    status: "watch",
    features: ["packet_rate", "iat_mean", "bytes_ratio"],
  },
  {
    id: "evt-1044",
    app: "unknown.uid.10284",
    destination: "new-destination.example",
    score: 0.82,
    severity: "high",
    status: "alert",
    features: ["burst_count", "flow_count", "dst_port"],
  },
];

function mapBackendItem(item: any, index: number): DemoEvent {
  const payload = item?.payload ?? item;
  const score = Number(payload?.anomaly_score ?? payload?.score ?? payload?.risk_score ?? 0);
  const rawSeverity = String(payload?.severity ?? (score > 0.75 ? "high" : score > 0.45 ? "medium" : "low")).toLowerCase();

  return {
    id: String(payload?.event_id ?? payload?.alert_id ?? item?.id ?? `backend-${index}`),
    app: String(payload?.app_id ?? payload?.package_name ?? "unknown app"),
    destination: String(payload?.destination_identity ?? payload?.site_hint ?? payload?.dst_ip ?? "metadata window"),
    score: Number.isFinite(score) ? Math.max(0, Math.min(score, 1)) : 0,
    severity: rawSeverity === "high" || rawSeverity === "medium" ? rawSeverity : "low",
    status: String(payload?.triage_status ?? payload?.status ?? "received").toLowerCase(),
    features: Array.isArray(payload?.top_features)
      ? payload.top_features.slice(0, 4).map(String)
      : ["metadata", "window", "score"],
  };
}

export default function DemoPage() {
  const [events, setEvents] = useState<DemoEvent[]>(seedEvents);
  const [token, setToken] = useState("");
  const [backendStatus, setBackendStatus] = useState("simulated stream");
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), 2200);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (token.trim()) return;

    setEvents((current) => {
      const next = current.map((event, index) => {
        const wave = Math.sin((tick + index) / 2.4);
        const score = Math.max(0.08, Math.min(0.94, event.score + wave * 0.035));
        return {
          ...event,
          score,
          severity: score > 0.74 ? "high" : score > 0.42 ? "medium" : "low",
          status: score > 0.74 ? "alert" : score > 0.42 ? "watch" : "normal",
        } satisfies DemoEvent;
      });
      return [...next].sort((a, b) => b.score - a.score);
    });
  }, [tick, token]);

  async function refreshFromBackend() {
    const cleanToken = token.trim();
    if (!cleanToken) {
      setBackendStatus("enter a backend token to read live same-origin API data");
      return;
    }

    try {
      setBackendStatus("loading backend data");
      const headers = { Authorization: `Bearer ${cleanToken}` };
      const [healthResponse, alertsResponse, eventsResponse] = await Promise.all([
        fetch("/health", { headers }),
        fetch("/api/v1/alerts?limit=20", { headers }),
        fetch("/api/v1/events/recent?limit=20", { headers }),
      ]);

      if (!healthResponse.ok) throw new Error(`health ${healthResponse.status}`);
      const alertsPayload = alertsResponse.ok ? await alertsResponse.json() : { alerts: [] };
      const eventsPayload = eventsResponse.ok ? await eventsResponse.json() : { items: [] };
      const alerts = Array.isArray(alertsPayload.alerts) ? alertsPayload.alerts : [];
      const items = Array.isArray(eventsPayload.items) ? eventsPayload.items : [];
      const mapped = [...alerts, ...items].slice(0, 8).map(mapBackendItem);

      setEvents(mapped.length ? mapped : seedEvents);
      setBackendStatus(mapped.length ? "connected to backend" : "backend connected, no live events yet");
    } catch (error) {
      setBackendStatus(error instanceof Error ? `backend unavailable: ${error.message}` : "backend unavailable");
    }
  }

  const averageScore = useMemo(() => {
    const total = events.reduce((sum, event) => sum + event.score, 0);
    return total / Math.max(events.length, 1);
  }, [events]);

  return (
    <section className="container demo-page">
      <div className="section-heading">
        <p className="eyebrow">Live demo</p>
        <h1>Watch metadata windows become anomaly decisions.</h1>
        <p>
          This page is designed for the public website. It runs a safe simulated stream by default, and it can
          read the real same-origin backend when you provide your private adapter token locally.
        </p>
      </div>

      <div className="demo-shell">
        <aside className="demo-controls">
          <div className="control-card">
            <span>Backend mode</span>
            <strong>{backendStatus}</strong>
            <label htmlFor="token">Adapter token</label>
            <input
              id="token"
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="only stored in this browser state"
            />
            <button className="button" type="button" onClick={refreshFromBackend}>
              Refresh backend data
            </button>
          </div>
          <div className="control-card">
            <span>Current mean score</span>
            <strong>{averageScore.toFixed(2)}</strong>
            <p>No payload text, URLs, message bodies, or packet contents are shown here.</p>
          </div>
        </aside>

        <div className="demo-feed">
          {events.map((event) => (
            <article className={`event-row severity-${event.severity}`} key={event.id}>
              <div>
                <span>{event.id}</span>
                <h2>{event.app}</h2>
                <p>{event.destination}</p>
              </div>
              <div className="feature-pills">
                {event.features.map((feature) => (
                  <span key={feature}>{feature}</span>
                ))}
              </div>
              <div className="score-block">
                <strong>{event.score.toFixed(2)}</strong>
                <span>{event.status}</span>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
