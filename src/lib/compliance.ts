// Compliance pivot: roll findings up by framework and control.

import type { Compliance, Finding } from "../types";
import { FRAMEWORKS } from "../types";

export interface FrameworkStat {
  key: keyof Compliance;
  label: string;
  mapped: number;
  passed: number;
  failed: number;
  failingControls: string[];
}

export function complianceRollup(findings: Finding[]): FrameworkStat[] {
  return FRAMEWORKS.map(({ key, label }) => {
    let mapped = 0;
    let passed = 0;
    let failed = 0;
    const failingControls = new Set<string>();

    for (const f of findings) {
      const controls = f.rule.compliance[key];
      if (!controls || controls.length === 0) continue;
      mapped++;
      if (f.status === "Passed") passed++;
      else if (f.status === "Failed") {
        failed++;
        controls.forEach((c) => failingControls.add(c));
      }
    }

    return { key, label, mapped, passed, failed, failingControls: [...failingControls].sort() };
  });
}
