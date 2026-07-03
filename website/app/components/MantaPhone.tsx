"use client";

import { useEffect, useState } from "react";

export type PhoneTab = "home" | "apps" | "alerts" | "settings";

type MantaPhoneProps = {
  autoPlay?: boolean;
  compact?: boolean;
  onActivity?: (message: string) => void;
};

const tabs: Array<{ id: PhoneTab; label: string; icon: string }> = [
  { id: "home", label: "Home", icon: "⌂" },
  { id: "apps", label: "Apps", icon: "▦" },
  { id: "alerts", label: "Alerts", icon: "!" },
  { id: "settings", label: "Settings", icon: "···" },
];

const appRows = [
  { name: "Telegram", packageName: "org.telegram.messenger", detail: "3 alerts · activity now", tone: "review" },
  { name: "Chrome", packageName: "com.android.chrome", detail: "428 flows · baseline stable", tone: "normal" },
  { name: "Google Maps", packageName: "com.google.android.apps.maps", detail: "91 flows · baseline stable", tone: "normal" },
];

export function MantaPhone({ autoPlay = false, compact = false, onActivity }: MantaPhoneProps) {
  const [tab, setTab] = useState<PhoneTab>("home");
  const [protection, setProtection] = useState(true);
  const [resolved, setResolved] = useState(false);
  const [privacy, setPrivacy] = useState<"Low" | "Medium" | "Strict">("Medium");
  const [flowCount, setFlowCount] = useState(1284);

  useEffect(() => {
    if (!autoPlay) return;
    const timer = window.setInterval(() => {
      setTab((current) => tabs[(tabs.findIndex((item) => item.id === current) + 1) % tabs.length].id);
      setFlowCount((count) => count + 7);
    }, 4200);
    return () => window.clearInterval(timer);
  }, [autoPlay]);

  function selectTab(next: PhoneTab) {
    setTab(next);
    onActivity?.(`Opened ${next}`);
  }

  function toggleProtection() {
    setProtection((current) => {
      onActivity?.(current ? "Paused local VPN capture" : "Started metadata-only VPN capture");
      return !current;
    });
  }

  function resolveAlert(label: string) {
    setResolved(true);
    onActivity?.(`${label}: feedback queued for model retraining`);
  }

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
          <span>Metadata-only endpoint monitor</span>
        </div>
        <b className={protection ? "online-dot" : "paused-dot"} aria-label={protection ? "Protection active" : "Protection paused"} />
      </div>

      <div className="phone-viewport" aria-live="polite">
        {tab === "home" && (
          <div className="phone-screen-content">
            <section className="protection-card">
              <div className="phone-status-line">
                <span className={protection ? "status-active" : "status-paused"}>
                  <i />
                  {protection ? "Protection active" : "Protection paused"}
                </span>
                <span className="shield-mark">◇</span>
              </div>
              <h3>{protection ? "Monitoring network behaviour" : "Capture is currently paused"}</h3>
              <p>Timing, volume and destination metadata are scored locally. Packet payloads are never inspected.</p>
              <button type="button" onClick={toggleProtection}>
                {protection ? "Pause capture" : "Start protection"}
              </button>
            </section>

            <div className="phone-metrics">
              <div><strong>{flowCount.toLocaleString()}</strong><span>flows today</span></div>
              <div><strong>{resolved ? 2 : 3}</strong><span>open alerts</span></div>
              <div><strong>0</strong><span>payloads read</span></div>
            </div>

            <div className="phone-section-title">
              <div><strong>Needs attention</strong><span>One high-confidence pattern</span></div>
              <button type="button" onClick={() => selectTab("alerts")}>Open</button>
            </div>

            <button className="attention-row" type="button" onClick={() => selectTab("alerts")}>
              <span className="risk-score">82</span>
              <span><strong>Telegram</strong><small>Rare destination · outbound burst</small></span>
              <b>{resolved ? "Reviewed" : "Review"}</b>
            </button>

            <div className="runtime-card">
              <strong>Runtime status</strong>
              <PhoneStatus label="On-device model" detail="Android RF · balanced" state="Ready" />
              <PhoneStatus label="Privacy export" detail={`${privacy} · identifiers hashed`} state="On" />
              <PhoneStatus label="Server backend" detail="Last sync 14 seconds ago" state="Online" />
            </div>
          </div>
        )}

        {tab === "apps" && (
          <div className="phone-screen-content">
            <PhoneIntro title="App activity" body="Per-app baselines, alert history and tuning profiles." />
            <div className="phone-filter-row">
              <button className="selected" type="button">User apps</button>
              <button type="button">Needs review</button>
            </div>
            {appRows.map((app) => (
              <article className="phone-app-row" key={app.packageName}>
                <span className={`app-monogram ${app.tone}`}>{app.name[0]}</span>
                <div><strong>{app.name}</strong><small>{app.packageName}</small><span>{app.detail}</span></div>
                <b className={app.tone}>{app.tone === "review" ? "Review" : "Normal"}</b>
              </article>
            ))}
          </div>
        )}

        {tab === "alerts" && (
          <div className="phone-screen-content">
            <PhoneIntro title="Alert triage" body="Metadata-window evidence without exposing payload content." />
            <article className={`phone-alert-card${resolved ? " resolved" : ""}`}>
              <div className="phone-alert-heading">
                <div><strong>Telegram</strong><span>High confidence · score 0.82</span></div>
                <b>{resolved ? "Reviewed" : "Open"}</b>
              </div>
              <p>A rare destination appeared during a sharp outbound burst. Local model output is combined with periodicity and novelty.</p>
              <Signal label="Destination novelty" value={91} tone="red" />
              <Signal label="Outbound byte spike" value={78} tone="amber" />
              <Signal label="Periodic beacon score" value={64} tone="teal" />
              <small>Observed 18:42 · No packet payload captured</small>
              {!resolved ? (
                <div className="phone-alert-actions">
                  <button type="button" onClick={() => resolveAlert("Marked dangerous")}>Dangerous</button>
                  <button type="button" onClick={() => resolveAlert("Marked false positive")}>False positive</button>
                </div>
              ) : (
                <div className="feedback-saved">✓ Feedback saved for retraining</div>
              )}
            </article>
          </div>
        )}

        {tab === "settings" && (
          <div className="phone-screen-content">
            <PhoneIntro title="Privacy and models" body="Control what leaves the device and how anomaly decisions are made." />
            <section className="privacy-card">
              <span>Privacy mode</span>
              <h3>{privacy}</h3>
              <p>
                {privacy === "Strict"
                  ? "Only reduced feature windows are exported. Endpoint context is removed."
                  : privacy === "Low"
                    ? "Readable app and site context remains; network addresses are hashed."
                    : "App and destination identifiers are hashed while timing and count features remain."}
              </p>
              <div className="privacy-options">
                {(["Low", "Medium", "Strict"] as const).map((level) => (
                  <button
                    className={privacy === level ? "selected" : ""}
                    type="button"
                    key={level}
                    onClick={() => {
                      setPrivacy(level);
                      onActivity?.(`Changed privacy mode to ${level}`);
                    }}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </section>
            <div className="runtime-card">
              <PhoneStatus label="Active detector" detail="Android RF · balanced" state="Local" />
              <PhoneStatus label="Shadow model" detail="Sequence detector" state="Compare" />
              <PhoneStatus label="Server endpoint" detail="bachelor.elfeel.me" state="Connected" />
              <PhoneStatus label="Export queue" detail="0 pending · 0 dead-letter" state="Clear" />
            </div>
          </div>
        )}
      </div>

      <nav className="phone-nav" aria-label="App navigation">
        {tabs.map((item) => (
          <button
            type="button"
            className={tab === item.id ? "selected" : ""}
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

function PhoneIntro({ title, body }: { title: string; body: string }) {
  return <div className="phone-intro"><h3>{title}</h3><p>{body}</p></div>;
}

function PhoneStatus({ label, detail, state }: { label: string; detail: string; state: string }) {
  return (
    <div className="phone-runtime-row">
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
