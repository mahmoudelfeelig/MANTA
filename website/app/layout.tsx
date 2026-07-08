import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "MANTA — Metadata-only mobile threat detection",
  description:
    "Bachelor thesis and working prototype for privacy-aware anomaly detection on encrypted Android traffic.",
};

const repoUrl = "https://github.com/Resistine/feel-bachelor";

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 .7a11.5 11.5 0 0 0-3.64 22.4c.58.1.79-.25.79-.56v-2.23c-3.22.7-3.9-1.37-3.9-1.37-.52-1.34-1.28-1.7-1.28-1.7-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.57-.29-5.27-1.28-5.27-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.16 1.18A10.9 10.9 0 0 1 12 6.12c.98 0 1.95.13 2.86.38 2.2-1.49 3.16-1.18 3.16-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.71 5.38-5.29 5.67.42.36.79 1.06.79 2.14v3.27c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .7Z"
      />
    </svg>
  );
}

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" data-scroll-behavior="smooth">
      <body>
        <header className="site-header">
          <div className="container nav-track">
            <Link href="/" className="brand" aria-label="MANTA home">
              <Image src="/elephant-logo.png" alt="" width={40} height={40} priority />
              <span>
                <strong>MANTA</strong>
                <small>Bachelor thesis · 2026</small>
              </span>
            </Link>
            <nav className="nav-links" aria-label="Primary navigation">
              <Link href="/#question">Question</Link>
              <Link href="/#system">System</Link>
              <Link href="/#evidence">Evidence</Link>
              <Link href="/demo">Interactive demo</Link>
            </nav>
            <a className="button button-compact button-dark" href="/manta-thesis.pdf" download>
              Thesis PDF
            </a>
          </div>
        </header>

        <main>{children}</main>

        <footer>
          <div className="container footer-bar">
            <div className="footer-mark">
              <Image src="/elephant-logo.png" alt="" width={30} height={30} />
              <small>© mahmoud elfeel 2026</small>
            </div>
            <p>Encrypted traffic. Observable behaviour. Explicit privacy trade-offs.</p>
            <a
              className="footer-github"
              href={repoUrl}
              aria-label="GitHub thesis repository"
              target="_blank"
              rel="noreferrer"
            >
              <GitHubIcon />
            </a>
          </div>
        </footer>
      </body>
    </html>
  );
}
