import { useMemo, useState } from "react";
import type { Store } from "../store";
import type { Rule, Severity } from "../types";
import { AVAILABLE_LISTS } from "../lib/engine";
import { Card, SeverityBadge } from "./ui";

const EXAMPLE = `{
  "id": "custom.super_users_strict",
  "domain": "Permissions",
  "severity": "High",
  "title": "Users with Super Permissions (strict org policy)",
  "description": "Our policy allows at most 5 users with combined super permissions.",
  "info": "Internal hardening standard HSD-12 caps super-permission holders at 5.",
  "remediation": "Reduce combined Modify All / View All / Manage Users holders to 5 or fewer.",
  "check": { "source": "soql", "kind": "count", "metric": "SuperUser", "op": "<=", "threshold": 5 },
  "compliance": { "NIST_800_53": ["AC-6(7)"], "SOC2": ["CC6.1"] },
  "tags": ["over-permissioning", "custom-policy"]
}`;

function validate(obj: unknown): { ok: true; rule: Rule } | { ok: false; error: string } {
  if (typeof obj !== "object" || obj === null) return { ok: false, error: "Must be a JSON object." };
  const o = obj as Record<string, unknown>;
  for (const field of ["id", "domain", "severity", "title", "check"]) {
    if (!(field in o)) return { ok: false, error: `Missing required field: "${field}".` };
  }
  if (!["High", "Medium", "Low"].includes(o.severity as string)) {
    return { ok: false, error: `"severity" must be High, Medium, or Low.` };
  }
  const c = o.check as Record<string, unknown>;
  if (!c || !["setting", "count", "listEmpty"].includes(c.kind as string)) {
    return { ok: false, error: `check.kind must be "setting", "count", or "listEmpty".` };
  }
  const rule: Rule = {
    id: String(o.id),
    domain: String(o.domain),
    severity: o.severity as Severity,
    title: String(o.title),
    description: String(o.description ?? ""),
    info: String(o.info ?? ""),
    remediation: String(o.remediation ?? ""),
    check: o.check as Rule["check"],
    compliance: (o.compliance as Rule["compliance"]) ?? {},
    tags: (o.tags as string[]) ?? [],
    custom: true,
  };
  return { ok: true, rule };
}

export function Rules({ store }: { store: Store }) {
  const [text, setText] = useState(EXAMPLE);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const add = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      setMsg({ kind: "err", text: `Invalid JSON: ${(e as Error).message}` });
      return;
    }
    const res = validate(parsed);
    if (!res.ok) {
      setMsg({ kind: "err", text: res.error });
      return;
    }
    store.addCustomRule(res.rule);
    setMsg({ kind: "ok", text: `Added "${res.rule.title}" and re-evaluated the org.` });
  };

  const sorted = useMemo(
    () => [...store.rules].sort((a, b) => (a.domain === b.domain ? a.title.localeCompare(b.title) : a.domain.localeCompare(b.domain))),
    [store.rules]
  );

  return (
    <div className="grid" style={{ gap: 16 }}>
      <Card title="Add a custom check" sub="Same schema as built-ins — no code change. Evaluated live against the connected org.">
        <div className="grid cols-2" style={{ alignItems: "start", gap: 16 }}>
          <div>
            <textarea className="input" rows={16} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
            <div className="row" style={{ marginTop: 10 }}>
              <button className="btn primary" onClick={add} disabled={!store.connected}>Add & evaluate</button>
              <button className="btn" onClick={() => setText(EXAMPLE)}>Reset example</button>
              {!store.connected && <span className="muted" style={{ fontSize: 12 }}>Connect an org first.</span>}
            </div>
            {msg && (
              <div style={{ marginTop: 10, fontSize: 13, color: msg.kind === "ok" ? "var(--pass)" : "var(--high)" }}>{msg.text}</div>
            )}
          </div>
          <div>
            <div className="section-label" style={{ marginTop: 0 }}>Supported check kinds</div>
            <div className="kv"><span className="k mono">setting</span><span>probe a config <span className="mono">path</span>, compare with <span className="mono">op</span> to <span className="mono">value</span></span></div>
            <div className="kv"><span className="k mono">count</span><span>resolve a <span className="mono">metric</span>, compare with <span className="mono">op</span> to <span className="mono">threshold</span></span></div>
            <div className="kv"><span className="k mono">listEmpty</span><span>pass when a named <span className="mono">list</span> is empty</span></div>
            <div className="section-label">Available count metrics</div>
            <div className="wrap">
              {["ViewAllData", "ModifyAllData", "ManageUsers", "BulkApiHardDelete", "WeeklyDataExport", "DeleteAccounts", "ViewPII"].map((m) => (
                <span key={m} className="tag mono">{m}</span>
              ))}
            </div>
            <div className="section-label">Available lists ({AVAILABLE_LISTS.length})</div>
            <div className="wrap">
              {AVAILABLE_LISTS.map((m) => (
                <span key={m} className="tag mono">{m}</span>
              ))}
            </div>
          </div>
        </div>
      </Card>

      <Card title={`Rule catalog (${store.rules.length})`} sub="Toggle any check on/off; scan updates immediately.">
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr><th>Enabled</th><th>Check</th><th>Domain</th><th>Sev</th><th>Source · kind</th><th></th></tr>
            </thead>
            <tbody>
              {sorted.map((r) => (
                <tr key={r.id}>
                  <td>
                    <span
                      className={`pill-filter ${r.enabled !== false ? "active" : ""}`}
                      onClick={() => store.toggleRule(r.id)}
                      style={{ minWidth: 44, textAlign: "center", display: "inline-block" }}
                    >
                      {r.enabled !== false ? "On" : "Off"}
                    </span>
                  </td>
                  <td>
                    {r.title}
                    {r.custom && <span className="badge neutral" style={{ marginLeft: 8 }}>custom</span>}
                    <div className="mono" style={{ fontSize: 11 }}>{r.id}</div>
                  </td>
                  <td className="muted">{r.domain}</td>
                  <td><SeverityBadge severity={r.severity} /></td>
                  <td className="mono">{r.check.source} · {r.check.kind}</td>
                  <td>{r.custom && <span className="close-x" onClick={() => store.removeCustomRule(r.id)} title="Remove">×</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
