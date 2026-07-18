import type { Store } from "../store";
import { Card, Bar } from "./ui";
import { complianceRollup } from "../lib/compliance";

export function Compliance({ store }: { store: Store }) {
  if (!store.connected) {
    return <Card><div className="empty">No scan yet. Run a scan from <b>Connections</b>.</div></Card>;
  }
  const stats = complianceRollup(store.findings);

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Card sub="Each finding is mapped to control IDs across six frameworks; this pivots your scan by framework.">
        <div style={{ fontSize: 13, color: "var(--text-dim)" }}>
          Failing controls are the specific clauses an auditor would flag. Export the CSV for the full control-level evidence.
        </div>
      </Card>

      <div className="grid cols-2">
        {stats.map((s) => {
          const pass = s.mapped > 0 ? (s.passed / s.mapped) * 100 : 0;
          const color = pass >= 80 ? "var(--pass)" : pass >= 55 ? "var(--med)" : "var(--high)";
          return (
            <Card key={s.key} title={s.label} sub={`${s.mapped} checks mapped · ${s.passed} passed · ${s.failed} failed`}>
              <div className="row" style={{ gap: 14, marginBottom: 14 }}>
                <div style={{ fontSize: 26, fontWeight: 750, color }}>{Math.round(pass)}%</div>
                <div style={{ flex: 1 }}><Bar value={pass} color={color} /></div>
              </div>
              {s.failingControls.length > 0 ? (
                <>
                  <div className="section-label" style={{ marginTop: 0 }}>Failing controls</div>
                  <div className="wrap">
                    {s.failingControls.map((c) => <span key={c} className="tag mono" style={{ color: "var(--high)" }}>{c}</span>)}
                  </div>
                </>
              ) : (
                <div className="muted" style={{ fontSize: 12 }}>No failing mapped controls.</div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
