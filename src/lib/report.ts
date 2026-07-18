// Exports findings as a Falcon-Shield-parity CSV (identical 27-column schema) so the
// output is a drop-in replacement for the reference report.

import type { Finding, OrgSnapshot } from "../types";
import { FRAMEWORKS } from "../types";
import { todayLabel } from "./format";

const COLUMNS = [
  "Status", "Integration", "Alias", "Security domain", "impact", "Affected", "Ratio",
  "Security check", "Description", "Info", "Remediation", "Status change date",
  "Business Owner", "Organization Domain", "ticket", "Creation Time", "Last Run",
  "Tags", "Check ID",
  ...FRAMEWORKS.map((f) => f.column),
  "Salesforce Guest User Security Policy Best Practices",
  "Falcon Shield SaaS NHI Benchmark",
];

function esc(v: string): string {
  if (v == null) return "";
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function toReportRows(findings: Finding[], snap: OrgSnapshot): string[][] {
  const now = todayLabel();
  return findings.map((f) => {
    const r = f.rule;
    const row: Record<string, string> = {
      Status: f.status,
      Integration: "Salesforce",
      Alias: snap.org.alias,
      "Security domain": r.domain,
      impact: r.severity,
      Affected: f.affected,
      Ratio: f.ratio,
      "Security check": r.title,
      Description: r.description,
      Info: r.info,
      Remediation: r.remediation,
      "Status change date": f.statusChangeDate ?? "",
      "Business Owner": snap.org.businessOwner,
      "Organization Domain": snap.org.instanceType,
      ticket: "",
      "Creation Time": now,
      "Last Run": now,
      Tags: (r.tags ?? []).join("; "),
      "Check ID": r.id,
      "Salesforce Guest User Security Policy Best Practices": (r.tags ?? []).includes("guest") ? "Applicable" : "",
      "Falcon Shield SaaS NHI Benchmark": (r.tags ?? []).includes("nhi") ? "Applicable" : "",
    };
    for (const fw of FRAMEWORKS) {
      row[fw.column] = (r.compliance[fw.key] ?? []).join(" ; ");
    }
    return COLUMNS.map((c) => row[c] ?? "");
  });
}

export function toCsv(findings: Finding[], snap: OrgSnapshot): string {
  const rows = toReportRows(findings, snap);
  const lines = [COLUMNS, ...rows].map((cols) => cols.map(esc).join(","));
  return lines.join("\r\n");
}

export function downloadCsv(findings: Finding[], snap: OrgSnapshot): void {
  const csv = toCsv(findings, snap);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `OrgLens_${snap.org.alias.replace(/[^a-z0-9]+/gi, "_")}_${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
