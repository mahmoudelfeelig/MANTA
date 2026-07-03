import Link from "next/link";

const thesisCards = [
  {
    label: "Problem",
    title: "Encrypted traffic limits payload inspection.",
    text: "Modern Android traffic is mostly encrypted. MANTA studies what can still be detected from flow metadata without reading message contents.",
  },
  {
    label: "Artifact",
    title: "Android endpoint, server backend, and ML pipeline.",
    text: "The implementation captures local flow windows, scores anomalies, exports privacy-tiered telemetry, and evaluates model utility against privacy leakage.",
  },
  {
    label: "Research question",
    title: "How much detection signal survives telemetry reduction?",
    text: "The thesis compares full and reduced feature views, on-device models, backend models, and observer leakage under reproducible public-corpus experiments.",
  },
];

const architecture = [
  ["Mobile Endpoint", "VpnService-based Android capture, local feature windows, consent controls, and on-device anomaly scoring."],
  ["Privacy Filter", "Export tiers decide which metadata features leave the device. Payload content is not inspected."],
  ["Server Backend", "Authenticated ingest, queueing, policy sync, model control, triage, and analyst feedback endpoints."],
  ["Evaluation Pipeline", "Public-dataset training, privacy views, leakage benchmarks, calibration, and reproducible evidence exports."],
];

const results = [
  ["6,034,487", "public-corpus flows"],
  ["904,371", "aggregated 60-second windows"],
  ["0.961", "high-recall Android RF F1"],
  ["0.135", "strict-view exact app leakage"],
];

export default function HomePage() {
  return (
    <>
      <section className="hero container">
        <div className="hero-copy">
          <p className="eyebrow">Bachelor thesis · Metadata-only mobile traffic monitoring</p>
          <h1>Detect mobile network anomalies without reading payloads.</h1>
          <p className="hero-text">
            MANTA measures the detection-privacy trade-off in encrypted Android traffic. The project asks
            whether flow metadata can provide useful anomaly signals while reducing the telemetry exported
            from the device.
          </p>
          <div className="hero-actions">
            <Link className="button" href="/demo">
              Open live demo
            </Link>
            <a className="button button-muted" href="/manta-thesis.pdf" download>
              Download thesis PDF
            </a>
          </div>
        </div>

        <div className="system-card" aria-label="MANTA system overview">
          <div className="phone-shell">
            <div className="phone-top" />
            <div className="phone-screen">
              <span>Android endpoint</span>
              <strong>Local windows</strong>
              <small>flow duration · ports · packet counts · timing</small>
            </div>
          </div>
          <div className="flow-line">
            <span />
            <span />
            <span className="blocked">payload hidden</span>
          </div>
          <div className="pipeline-stack">
            <div>
              <span>Privacy filter</span>
              <strong>metadata only</strong>
            </div>
            <div>
              <span>Server backend</span>
              <strong>ingest · policy · triage</strong>
            </div>
            <div className="score-row">
              <span>Anomaly score</span>
              <strong>0.82</strong>
            </div>
          </div>
        </div>
      </section>

      <section id="thesis" className="container section">
        <div className="section-heading">
          <p className="eyebrow">Overall thesis</p>
          <h2>What the website should explain first.</h2>
        </div>
        <div className="card-grid">
          {thesisCards.map((card) => (
            <article className="card" key={card.label}>
              <span>{card.label}</span>
              <h3>{card.title}</h3>
              <p>{card.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="architecture" className="container section">
        <div className="section-heading">
          <p className="eyebrow">Architecture</p>
          <h2>Four parts, one measurement question.</h2>
        </div>
        <div className="architecture-list">
          {architecture.map(([title, text]) => (
            <article className="architecture-item" key={title}>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="results" className="container section results-section">
        <div className="section-heading">
          <p className="eyebrow">Evaluation snapshot</p>
          <h2>Results are framed as a trade-off, not a magic privacy claim.</h2>
          <p>
            MANTA reduces exported telemetry and measures the utility loss. It also documents that passive
            traffic analysis remains a serious limitation, even when payloads are never inspected.
          </p>
        </div>
        <div className="metric-grid">
          {results.map(([value, label]) => (
            <div className="metric" key={label}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
