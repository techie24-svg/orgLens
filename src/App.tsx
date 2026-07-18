import { useState } from "react";
import { useStore } from "./store";
import { Dashboard } from "./components/Dashboard";
import { Findings } from "./components/Findings";
import { Compliance } from "./components/Compliance";
import { Rules } from "./components/Rules";
import { Connections } from "./components/Connections";
import { downloadCsv } from "./lib/report";

type View = "Connections" | "Dashboard" | "Findings" | "Compliance" | "Rules";

const NAV: { id: View; label: string }[] = [
  { id: "Connections", label: "Connections" },
  { id: "Dashboard", label: "Dashboard" },
  { id: "Findings", label: "Findings" },
  { id: "Compliance", label: "Compliance" },
  { id: "Rules", label: "Rule Catalog" },
];

const SUBTITLES: Record<View, string> = {
  Connections: "Connect an org via OAuth and run a posture scan",
  Dashboard: "Security posture score, domains, and drift",
  Findings: "Every check, its result, and guided remediation",
  Compliance: "Findings pivoted across six frameworks",
  Rules: "Built-in and custom checks — add your own",
};

export function App() {
  const store = useStore();
  const [view, setView] = useState<View>("Connections");

  const canExport = store.connected && store.findings.length > 0;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">◎</div>
          <div>
            <div className="brand-name">OrgLens</div>
            <div className="brand-sub">Salesforce SSPM</div>
          </div>
        </div>
        {NAV.map((n) => (
          <div
            key={n.id}
            className={`nav-item ${view === n.id ? "active" : ""}`}
            onClick={() => setView(n.id)}
          >
            <span className="dot" />
            {n.label}
          </div>
        ))}
        <div className="nav-spacer" />
        <div className="nav-foot">
          {store.connected ? (
            <>Connected · {store.rules.filter((r) => r.enabled !== false).length} active checks<br />Last run: {store.lastRun ?? "—"}</>
          ) : (
            <>Not connected<br />Go to Connections to scan.</>
          )}
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div>
            <h1>{view}</h1>
            <div className="sub">{SUBTITLES[view]}</div>
          </div>
          <div className="row">
            {store.connected && (
              <button className="btn" onClick={store.rescan} disabled={store.scanning}>
                {store.scanning ? "Scanning…" : "Re-scan"}
              </button>
            )}
            <button
              className="btn primary"
              disabled={!canExport}
              onClick={() => store.snapshot && downloadCsv(store.findings, store.snapshot)}
            >
              Export report (CSV)
            </button>
          </div>
        </div>

        <div className="content">
          {view === "Connections" && <Connections store={store} onScanned={() => setView("Dashboard")} />}
          {view === "Dashboard" && <Dashboard store={store} />}
          {view === "Findings" && <Findings store={store} />}
          {view === "Compliance" && <Compliance store={store} />}
          {view === "Rules" && <Rules store={store} />}
        </div>
      </main>
    </div>
  );
}
