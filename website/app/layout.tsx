import type { Metadata, Viewport } from "next";
import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "MANTA Thesis",
  description:
    "Bachelor thesis website for MANTA, a metadata-only mobile traffic monitoring and anomaly detection project.",
  icons: {
    icon: "/favicon.ico",
    shortcut: "/favicon.ico",
    apple: "/elephant-logo.png",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark",
};

const repoUrl = "https://github.com/Resistine/feel-bachelor";

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        fill="currentColor"
        d="M12 2C6.48 2 2 6.59 2 12.25c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49 0-.24-.01-.88-.01-1.73-2.78.62-3.37-1.37-3.37-1.37-.45-1.18-1.11-1.5-1.11-1.5-.91-.63.07-.62.07-.62 1 .07 1.53 1.06 1.53 1.06.9 1.56 2.35 1.11 2.92.85.09-.67.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.7 0 0 .84-.28 2.75 1.05A9.36 9.36 0 0 1 12 6.98c.85 0 1.7.12 2.5.34 1.9-1.33 2.74-1.05 2.74-1.05.55 1.4.2 2.44.1 2.7.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.8-4.57 5.05.36.32.68.95.68 1.92 0 1.38-.01 2.5-.01 2.84 0 .27.18.59.69.49A10.15 10.15 0 0 0 22 12.25C22 6.59 17.52 2 12 2Z"
      />
    </svg>
  );
}

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <div className="container nav-track">
            <Link href="/" className="brand" aria-label="MANTA home">
              <Image src="/elephant-logo.png" alt="" width={38} height={38} priority />
              <span>MANTA</span>
            </Link>
            <nav className="nav-links" aria-label="Primary navigation">
              <Link href="/#thesis">Thesis</Link>
              <Link href="/#architecture">Architecture</Link>
              <Link href="/#results">Results</Link>
              <Link href="/demo">Demo</Link>
            </nav>
            <a className="button button-compact" href="/manta-thesis.pdf" download>
              Download PDF
            </a>
          </div>
        </header>

        <main>{children}</main>

        <footer>
          <div className="container footer-bar">
            <div className="footer-mark">
              <Image src="/elephant-logo.png" alt="" width={28} height={28} />
              <small>© mahmoud elfeel 2026</small>
            </div>
            <a
              className="footer-github"
              href={repoUrl}
              aria-label="GitHub repository"
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
