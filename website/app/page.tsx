import Link from "next/link";
import { MantaPhone } from "./components/MantaPhone";

const metrics = [
  ["6.03M", "public-corpus flows processed"],
  ["904k", "60-second behaviour windows"],
  ["0.961", "high-recall Android RF F1"],
  ["0.135", "strict-view exact app leakage"],
];

const layers = [
  {
    number: "01",
    title: "Android endpoint",
    text: "A VpnService observes packet metadata, attributes flows to apps and builds 60-second feature windows without storing payload content.",
    output: "Local window",
  },
  {
    number: "02",
    title: "On-device decision",
    text: "Statistical, tree, sequence and multivariate detectors score behaviour against local and per-app baselines.",
    output: "Score + evidence",
  },
  {
    number: "03",
    title: "Privacy boundary",
    text: "Low, medium, strict and custom policies control which identifiers and feature details may leave the phone.",
    output: "Reduced telemetry",
  },
  {
    number: "04",
    title: "Server assistance",
    text: "Authenticated ingest, heavier inference, policy sync, analyst triage and feedback support the endpoint without replacing it.",
    output: "Policy + feedback",
  },
];

export default function HomePage() {
  return (
    <>
      <section className="hero hero-editorial container">
        <div className="hero-copy">
          <div className="issue-line">
            <span>Computer science bachelor thesis</span>
            <span>HTW Berlin · 2026</span>
          </div>
          <p className="eyebrow">Mobile anomaly and network threat analysis</p>
          <h1>
            Detect the change.
            <em>Keep the payload private.</em>
          </h1>
          <p className="hero-text">
            MANTA is a working Android endpoint monitor and research prototype. It tests whether encrypted
            mobile traffic can be scored from behavioural metadata while reducing what the device exports.
          </p>
          <div className="hero-actions">
            <Link className="button button-primary" href="/demo">
              Use the interactive app
            </Link>
            <a className="text-link" href="/manta-thesis.pdf" download>
              Read the thesis <span>↗</span>
            </a>
          </div>
          <div className="hero-proof">
            <span><i /> Android prototype</span>
            <span><i /> Server endpoint</span>
            <span><i /> Reproducible ML pipeline</span>
          </div>
        </div>

        <div className="hero-device">
          <div className="hero-device-note note-top">Real app structure</div>
          <MantaPhone autoPlay compact />
          <div className="hero-device-note note-bottom">No payload inspection</div>
        </div>
      </section>

      <section id="question" className="question-section">
        <div className="container question-grid">
          <div>
            <p className="eyebrow eyebrow-dark">The research question</p>
            <h2>How much useful detection signal survives when telemetry is reduced?</h2>
          </div>
          <div className="question-copy">
            <p>
              TLS hides content from payload inspection, but timing, direction, volume, protocol and destination
              behaviour remain observable. MANTA measures whether those signals can identify anomalous mobile
              behaviour without pretending that metadata is harmless.
            </p>
            <p>
              The evaluation compares full and privacy-reduced feature views, on-device and server models,
              detection utility and observer leakage on public traffic corpora.
            </p>
          </div>
        </div>
      </section>

      <section id="system" className="container section system-section">
        <div className="section-heading split-heading">
          <div>
            <p className="eyebrow">System, not concept art</p>
            <h2>One traffic window through the actual stack.</h2>
          </div>
          <p>
            Each layer corresponds to implemented Android, server or ML-pipeline code in the thesis repository.
          </p>
        </div>
        <div className="system-flow">
          {layers.map((layer) => (
            <article key={layer.number}>
              <span className="flow-number">{layer.number}</span>
              <div>
                <h3>{layer.title}</h3>
                <p>{layer.text}</p>
              </div>
              <strong>{layer.output}</strong>
            </article>
          ))}
        </div>
      </section>

      <section className="demo-film-section">
        <div className="container demo-film-grid">
          <div className="film-copy">
            <p className="eyebrow eyebrow-dark">Functional walkthrough</p>
            <h2>The phone is the product surface.</h2>
            <p>
              Start metadata-only capture, inspect app baselines, review an explained alert, label the outcome
              and change the export privacy mode. The interactive demo uses the same information architecture.
            </p>
            <Link className="button button-ink" href="/demo">Open full demo</Link>
          </div>
          <div className="film-frame">
            <video
              src="/manta-app-demo.mp4"
              controls
              muted
              loop
              playsInline
              preload="metadata"
              aria-label="MANTA Android application walkthrough"
            />
            <div className="film-caption">
              <span>00:22</span>
              <p>Capture → app activity → alert evidence → privacy mode</p>
            </div>
          </div>
        </div>
      </section>

      <section id="evidence" className="container section evidence-section">
        <div className="section-heading split-heading">
          <div>
            <p className="eyebrow">Evaluation snapshot</p>
            <h2>Utility and leakage are reported together.</h2>
          </div>
          <p>
            A reduced export is not a privacy guarantee. The thesis measures model performance and explicitly
            documents what traffic patterns remain visible to a passive observer.
          </p>
        </div>
        <div className="metric-grid">
          {metrics.map(([value, label], index) => (
            <div className="metric" key={label}>
              <span>0{index + 1}</span>
              <strong>{value}</strong>
              <p>{label}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="container thesis-cta">
        <div>
          <p className="eyebrow">Read the complete argument</p>
          <h2>Methods, limitations, evidence and implementation details.</h2>
        </div>
        <a className="button button-primary" href="/manta-thesis.pdf" download>
          Download thesis PDF
        </a>
      </section>
    </>
  );
}
