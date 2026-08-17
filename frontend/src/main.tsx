import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const apiBaseUrl = import.meta.env.VITE_DFIRWB_API_URL ?? "http://127.0.0.1:8080";

function App() {
  const [status, setStatus] = useState("Not checked");

  async function checkApi() {
    setStatus("Checking…");
    try {
      const response = await fetch(`${apiBaseUrl}/healthz`);
      setStatus(response.ok ? "API healthy" : `API returned HTTP ${response.status}`);
    } catch {
      setStatus("API unavailable");
    }
  }

  return (
    <main>
      <p className="eyebrow">DFIR Evidence Workbench</p>
      <h1>Evidence, provenance, and review in one place.</h1>
      <p className="lede">
        The frontend is a thin client for the authenticated API. Tenant scope and analyst identity
        remain server-enforced; this browser never selects a tenant.
      </p>
      <section className="status-card" aria-live="polite">
        <div>
          <span className="label">API status</span>
          <strong>{status}</strong>
        </div>
        <button type="button" onClick={checkApi}>
          Check API
        </button>
      </section>
      <p className="caption">Endpoint: {apiBaseUrl}</p>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
