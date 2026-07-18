import type { Store } from "../store";
import { Card, Kpi, ScoreRing, Bar, SeverityBadge } from "./ui";
import { rollup } from "../lib/score";
import { SEVERITY_ORDER } from "../lib/format";

function EmptyState() {
  return (
    <Card>
      <div className="empty">No scan yet. Go to <b>Connections</b> and run a scan to see your posture.</div>
    </Card>
  );
}

export function Dashboard({ store }: { store: Store }) {
  if (!store.connected) return <EmptyState />;
  const r = rollup(store.findings);
  const drift = store.findings.filter((f) => f.statusChangeDate).length;
  const highFailed = r.bySeverity.High.failed;

  const topFailures = store.findings
    .filter((f) => f.status === "Failed")
    .sort((a, b) => SEVERITY_ORDER[a.rule.severity] - SEVERITY_ORDER[b.rule.severity])
    .slice(0, 6);

  function domainColor(score: number) {
    if (score >= 80) return "var(--pass)";
    if (score >= 55) return "var(--med)";
    return "var(--high)";
  }

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-4">
        <Card>
          <div className="score-wrap">
            <ScoreRing score={r.score} />
            <div>
              <div className="kpi-label">Posture score</div>
              <div className="kpi-hint" style={{ marginTop: 6 }}>Severity-weighted<br />pass ratio</div>
            </div>
          </div>
        </Card>
        <Kpi label="Failed checks" value={r.failed} hint={`of ${r.passed + r.failed} evaluated`} tone="var(--high)" />
        <Kpi label="High-severity failures" value={highFailed} hint="prioritize these first" tone={highFailed ? "var(--high)" : "var(--pass)"} />
        <Kpi label="Changed since last scan" value={drift} hint="configuration drift" tone={drift ? "var(--med)" : undefined} />
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <Card title="Security domains" sub="Pass rate by domain — worst first">
          <div className="grid" style={{ gap: 12 }}>
            {r.byDomain.map((d) => (
              <div key={d.domain}>
                <div className="row" style={{ justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontWeight: 550 }}>{d.domain}</span>
                  <span className="muted" style={{ fontSize: 12 }}>{d.passed}/{d.passed + d.failed} · {Math.round(d.score)}%</span>
                </div>
                <Bar value={d.score} color={domainColor(d.score)} />
              </div>
            ))}
          </div>
        </Card>

        <div className="grid" style={{ gap: 16 }}>
          <Card title="By severity">
            <table className="tbl">
              <thead><tr><th>Severity</th><th>Passed</th><th>Failed</th></tr></thead>
              <tbody>
                {(["High", "Medium", "Low"] as const).map((s) => (
                  <tr key={s}>
                    <td><SeverityBadge severity={s} /></td>
                    <td style={{ color: "var(--pass)" }}>{r.bySeverity[s].passed}</td>
                    <td style={{ color: r.bySeverity[s].failed ? "var(--high)" : "var(--text-dim)" }}>{r.bySeverity[s].failed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card title="Top failures to remediate">
            <div className="grid" style={{ gap: 8 }}>
              {topFailures.map((f) => (
                <div key={f.rule.id} className="row" style={{ justifyContent: "space-between", gap: 10 }}>
                  <span style={{ fontSize: 13 }}>{f.rule.title}</span>
                  <SeverityBadge severity={f.rule.severity} />
                </div>
              ))}
              {topFailures.length === 0 && <div className="muted">No failures — nice.</div>}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
