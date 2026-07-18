// Posture scoring: severity-weighted pass ratio, plus per-domain and per-severity rollups.

import type { Finding, Severity } from "../types";

const WEIGHT: Record<Severity, number> = { High: 5, Medium: 3, Low: 1 };

export interface DomainStat {
  domain: string;
  passed: number;
  failed: number;
  total: number;
  score: number;
}

export interface Rollup {
  score: number;
  passed: number;
  failed: number;
  notEval: number;
  total: number;
  bySeverity: Record<Severity, { passed: number; failed: number }>;
  byDomain: DomainStat[];
}

export function rollup(findings: Finding[]): Rollup {
  let wEarned = 0;
  let wPossible = 0;
  let passed = 0;
  let failed = 0;
  let notEval = 0;

  const bySeverity: Record<Severity, { passed: number; failed: number }> = {
    High: { passed: 0, failed: 0 },
    Medium: { passed: 0, failed: 0 },
    Low: { passed: 0, failed: 0 },
  };
  const domains = new Map<string, DomainStat>();

  for (const f of findings) {
    const sev = f.rule.severity;
    const d = domains.get(f.rule.domain) ?? { domain: f.rule.domain, passed: 0, failed: 0, total: 0, score: 0 };
    d.total++;

    if (f.status === "Not Evaluated") {
      notEval++;
    } else {
      wPossible += WEIGHT[sev];
      if (f.status === "Passed") {
        passed++;
        wEarned += WEIGHT[sev];
        bySeverity[sev].passed++;
        d.passed++;
      } else {
        failed++;
        bySeverity[sev].failed++;
        d.failed++;
      }
    }
    domains.set(f.rule.domain, d);
  }

  const byDomain = [...domains.values()].map((d) => ({
    ...d,
    score: d.passed + d.failed > 0 ? (d.passed / (d.passed + d.failed)) * 100 : 0,
  }));
  byDomain.sort((a, b) => a.score - b.score);

  return {
    score: wPossible > 0 ? (wEarned / wPossible) * 100 : 0,
    passed,
    failed,
    notEval,
    total: findings.length,
    bySeverity,
    byDomain,
  };
}
