import { Link } from "react-router-dom";

const capabilities = [
  {
    title: "Client-side AES-GCM encryption",
    description:
      "Files are encrypted in the browser before upload, keeping plaintext away from server infrastructure.",
  },
  {
    title: "Fragment-key secure sharing",
    description:
      "Decryption keys travel in URL fragments (#k=...), so backend logs and proxies never receive key material.",
  },
  {
    title: "Policy-driven access controls",
    description:
      "Set expiration windows, one-time access, download quotas, optional passwords, and instant revocation.",
  },
  {
    title: "Integrity and audit visibility",
    description:
      "Ciphertext hashes validate payload integrity while access logs expose denied/granted attempts with reasons.",
  },
];

const timeline = [
  "1. Select file and encrypt locally in your browser.",
  "2. Upload ciphertext plus minimal encrypted metadata.",
  "3. Generate a secure share link with optional controls.",
  "4. Recipient decrypts only in browser with fragment key.",
];

export default function LandingPage({ isAuthenticated }) {
  return (
    <main className="page landing-page">
      <section className="hero-panel reveal-up landing-hero">
        <p className="eyebrow">VaultMesh • Zero-Knowledge File Platform</p>
        <h1>Secure sharing that never exposes plaintext to your server</h1>
        <p className="hero-copy">
          A full-stack React and Node.js system designed for privacy-first operations,
          combining practical usability with enterprise-grade encryption workflow.
        </p>
        <div className="hero-actions">
          <Link className="btn primary" to={isAuthenticated ? "/dashboard" : "/auth"}>
            {isAuthenticated ? "Open dashboard" : "Start securely"}
          </Link>
          <Link className="btn ghost" to="/auth">
            Owner portal
          </Link>
        </div>
      </section>

      <section className="grid-two">
        {capabilities.map((item) => (
          <article key={item.title} className="panel capability reveal-up">
            <h2>{item.title}</h2>
            <p className="muted">{item.description}</p>
          </article>
        ))}
      </section>

      <section className="panel architecture reveal-up">
        <h2>How the zero-knowledge flow works</h2>
        <div className="timeline-grid">
          {timeline.map((step) => (
            <p className="status" key={step}>
              {step}
            </p>
          ))}
        </div>
      </section>

      <section className="panel cta-strip reveal-up">
        <h2>Ready for your final project presentation</h2>
        <p className="muted">
          The website includes frontend + backend architecture, secure file lifecycle,
          and policy controls that demonstrate practical zero-knowledge design.
        </p>
        <Link className="btn primary" to={isAuthenticated ? "/dashboard" : "/auth"}>
          Continue to application
        </Link>
      </section>
    </main>
  );
}
