import { useMemo, useState } from "react";
import type { Store } from "../store";
import type { Finding, Severity, Status } from "../types";
import { FRAMEWORKS } from "../types";
import { Card, SeverityBadge, StatusBadge } from "./ui";
import { SEVERITY_ORDER } from "../lib/format";

type StatusFilter = "All" | Status;
type SevFilter = "All" | Severity;
type SortKey = "status" | "severity" | "title" | "domain" | "affected" | "ratio";

const STATUS_FILTERS: StatusFilter[] = ["All", "Failed", "Passed", "Not Evaluated"];

/** Worst-first, so the default sort surfaces what needs action. */
const STATUS_ORDER: Record<Status, number> = { Failed: 0, "Not Evaluated": 1, Passed: 2 };

const COLUMNS: { key: SortKey | null; label: string }[] = [
  { key: "status", label: "Status" },
  { key: "severity", label: "Sev" },
  { key: "title", label: "Security check" },
  { key: "domain", label: "Domain" },
  { key: "affected", label: "Affected" },
  { key: "ratio", label: "Ratio" },
  { key: null, label: "" },
];

/**
 * Ratios read like "7/16" or "—". Sort by the numerator so the biggest blast
 * radius rises to the top, and push the placeholder rows to the end.
 */
function ratioValue(ratio: string): number {
  const n = parseInt(ratio, 10);
  return Number.isNaN(n) ? -1 : n;
}

function compareBy(key: SortKey, a: Finding, b: Finding): number {
  switch (key) {
    case "status": return STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
    case "severity": return SEVERITY_ORDER[a.rule.severity] - SEVERITY_ORDER[b.rule.severity];
    case "title": return a.rule.title.localeCompare(b.rule.title);
    case "domain": return a.rule.domain.localeCompare(b.rule.domain);
    case "affected": return a.affected.localeCompare(b.affected);
    case "ratio": return ratioValue(b.ratio) - ratioValue(a.ratio);
  }
}

export function Findings({ store }: { store: Store }) {
  const [status, setStatus] = useState<StatusFilter>("Failed");
  const [sev, setSev] = useState<SevFilter>("All");
  const [domain, setDomain] = useState<string>("All");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);

  // First click sorts by a column's natural direction; clicking the active
  // column again reverses it.
  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc((prev) => !prev);
    else { setSortKey(key); setSortAsc(true); }
  };

  const domains = useMemo(
    () => ["All", ...Array.from(new Set(store.findings.map((f) => f.rule.domain)))],
    [store.findings]
  );

  const rows = useMemo(() => {
    return store.findings
      .filter((f) => (status === "All" ? true : f.status === status))
      .filter((f) => (sev === "All" ? true : f.rule.severity === sev))
      .filter((f) => (domain === "All" ? true : f.rule.domain === domain))
      .filter((f) => (q ? (f.rule.title + f.rule.id).toLowerCase().includes(q.toLowerCase()) : true))
      .sort((a, b) => {
        if (sortKey) {
          const cmp = compareBy(sortKey, a, b);
          if (cmp !== 0) return sortAsc ? cmp : -cmp;
          return a.rule.title.localeCompare(b.rule.title);
        }
        // Default: worst status first, then severity.
        if (a.status !== b.status) return STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
        return SEVERITY_ORDER[a.rule.severity] - SEVERITY_ORDER[b.rule.severity];
      });
  }, [store.findings, status, sev, domain, q, sortKey, sortAsc]);

  if (!store.connected) {
    return <Card><div className="empty">No scan yet. Run a scan from <b>Connections</b>.</div></Card>;
  }

  return (
    <>
      <Card>
        <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div className="wrap">
            {STATUS_FILTERS.map((s) => (
              <span key={s} className={`pill-filter ${status === s ? "active" : ""}`} onClick={() => setStatus(s)}>{s}</span>
            ))}
            <span style={{ width: 8 }} />
            {(["All", "High", "Medium", "Low"] as SevFilter[]).map((s) => (
              <span key={s} className={`pill-filter ${sev === s ? "active" : ""}`} onClick={() => setSev(s)}>{s}</span>
            ))}
          </div>
          <div className="row">
            <select className="select" style={{ width: 190 }} value={domain} onChange={(e) => setDomain(e.target.value)}>
              {domains.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
            <input className="input" style={{ width: 200 }} placeholder="Search checks…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>

        <div style={{ marginTop: 16, overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                {COLUMNS.map((col) =>
                  col.key === null ? (
                    <th key="chevron" />
                  ) : (
                    <th
                      key={col.key}
                      className={`sortable ${sortKey === col.key ? "sorted" : ""}`}
                      onClick={() => toggleSort(col.key as SortKey)}
                      aria-sort={sortKey === col.key ? (sortAsc ? "ascending" : "descending") : "none"}
                    >
                      {col.label}
                      <span className="sort-caret">
                        {sortKey === col.key ? (sortAsc ? "▲" : "▼") : "↕"}
                      </span>
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.rule.id} className="clickable" onClick={() => setSelected(f)}>
                  <td><StatusBadge status={f.status} /></td>
                  <td><SeverityBadge severity={f.rule.severity} /></td>
                  <td>
                    {f.rule.title}
                    {f.statusChangeDate && <span className="badge drift" style={{ marginLeft: 8 }}>changed</span>}
                    {f.rule.custom && <span className="badge neutral" style={{ marginLeft: 8 }}>custom</span>}
                  </td>
                  <td className="muted">{f.rule.domain}</td>
                  <td className="muted" style={{ maxWidth: 220 }}>{f.affected}</td>
                  <td className="mono">{f.ratio}</td>
                  <td className="muted">›</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={7}><div className="empty">No checks match these filters.</div></td></tr>}
            </tbody>
          </table>
        </div>
        <div className="muted" style={{ marginTop: 12, fontSize: 12 }}>{rows.length} of {store.findings.length} checks shown</div>
      </Card>

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const r = finding.rule;
  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div className="wrap" style={{ marginBottom: 8 }}>
              <StatusBadge status={finding.status} />
              <SeverityBadge severity={r.severity} />
              <span className="badge neutral">{r.domain}</span>
              {finding.statusChangeDate && <span className="badge drift">changed {finding.statusChangeDate}</span>}
            </div>
            <h2>{r.title}</h2>
            <p className="mono" style={{ fontSize: 12 }}>{r.id}</p>
          </div>
          <button className="close-x" onClick={onClose}>×</button>
        </div>

        <div className="section-label">What & why</div>
        <p>{r.info}</p>

        <div className="section-label">Result</div>
        <div className="kv"><span className="k">Status</span><span>{finding.status}</span></div>
        <div className="kv"><span className="k">Observed</span><span>{finding.actual}</span></div>
        <div className="kv"><span className="k">Affected</span><span>{finding.affected}</span></div>
        <div className="kv"><span className="k">Ratio</span><span className="mono">{finding.ratio}</span></div>
        <div className="kv"><span className="k">Source</span><span className="mono">{r.check.source}</span></div>

        <div className="section-label">Remediation</div>
        <p>{r.remediation}</p>

        <div className="section-label">Compliance mapping</div>
        {FRAMEWORKS.map((fw) => {
          const controls = r.compliance[fw.key];
          if (!controls || controls.length === 0) return null;
          return (
            <div className="kv" key={fw.key}>
              <span className="k">{fw.label}</span>
              <span className="mono">{controls.join(", ")}</span>
            </div>
          );
        })}
        {r.tags && r.tags.length > 0 && (
          <>
            <div className="section-label">Tags</div>
            <div className="wrap">{r.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
          </>
        )}
      </div>
    </div>
  );
}
