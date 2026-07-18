// Rule engine: evaluates declarative rules against an OrgSnapshot to produce Findings.
// The same evaluator runs built-in and user-authored rules.

import type { Finding, Op, OrgSnapshot, Rule, Status } from "../types";

function compare(actual: number | boolean | string, op: Op, expected: number | boolean | string): boolean {
  switch (op) {
    case "==": return actual === expected;
    case "!=": return actual !== expected;
    case "<=": return Number(actual) <= Number(expected);
    case ">=": return Number(actual) >= Number(expected);
    case "<": return Number(actual) < Number(expected);
    case ">": return Number(actual) > Number(expected);
  }
}

/** Derived lists referenced by `listEmpty` checks. */
function resolveList(snap: OrgSnapshot, key: string): string[] {
  switch (key) {
    case "oauthFullScopeApps":
      return snap.connectedApps.filter((a) => a.scopes.includes("full")).map((a) => a.name);
    case "connectedAppsIpRelax":
      return snap.connectedApps.filter((a) => a.ipRelaxation === "RELAX").map((a) => a.name);
    case "connectedAppsNonExpiring":
      return snap.connectedApps.filter((a) => a.usesNonExpiringRefreshTokens).map((a) => a.name);
    case "objectsPublicExternal":
      return snap.objectsPublicExternal;
    case "publicLinksNoPassword":
      return snap.publicLinksNoPassword;
    case "guestSharingRules":
      return snap.guestSharingRules;
    default:
      return [];
  }
}

function truncateList(items: string[], max = 5): string {
  if (items.length === 0) return "None";
  const head = items.slice(0, max).join(", ");
  return items.length > max ? `${head} +${items.length - max} more` : head;
}

export interface EvalResult {
  status: Status;
  affected: string;
  ratio: string;
  actual: string;
}

const NOT_EVALUATED: EvalResult = { status: "Not Evaluated", affected: "—", ratio: "—", actual: "unavailable" };

export function evaluateRule(rule: Rule, snap: OrgSnapshot): EvalResult {
  const c = rule.check;
  const u = snap.unavailable;
  try {
    if (c.kind === "setting") {
      if (!c.path || c.op === undefined || c.value === undefined || !(c.path in snap.settings)) {
        return NOT_EVALUATED;
      }
      if (u?.settings?.includes(c.path)) return NOT_EVALUATED;
      const actual = snap.settings[c.path];
      const pass = compare(actual, c.op, c.value);
      return { status: pass ? "Passed" : "Failed", affected: "Global", ratio: "Global", actual: String(actual) };
    }

    if (c.kind === "count") {
      if (!c.metric || c.op === undefined || c.threshold === undefined) {
        return NOT_EVALUATED;
      }
      if (u?.metrics?.includes(c.metric)) return NOT_EVALUATED;
      const count = snap.permissionCounts[c.metric] ?? 0;
      const pass = compare(count, c.op, c.threshold);
      const affected = snap.permissionAffected[c.metric] ?? [];
      return {
        status: pass ? "Passed" : "Failed",
        affected: pass ? "Within threshold" : truncateList(affected),
        ratio: `${count}/${snap.totalActiveUsers}`,
        actual: `${count} users (threshold ${c.op} ${c.threshold})`,
      };
    }

    // listEmpty
    if (c.list && u?.lists?.includes(c.list)) return NOT_EVALUATED;
    const items = resolveList(snap, c.list ?? "");
    const pass = items.length === 0;
    return {
      status: pass ? "Passed" : "Failed",
      affected: truncateList(items),
      ratio: pass ? "0 found" : `${items.length} found`,
      actual: pass ? "none" : truncateList(items),
    };
  } catch {
    return { status: "Not Evaluated", affected: "—", ratio: "—", actual: "error" };
  }
}

/** Evaluate all enabled rules; optionally diff against a previous run for drift. */
export function runScan(rules: Rule[], snap: OrgSnapshot, previous?: Map<string, Status>): Finding[] {
  const today = new Date().toISOString().slice(0, 10);
  return rules
    .filter((r) => r.enabled !== false)
    .map((rule) => {
      const res = evaluateRule(rule, snap);
      const prev = previous?.get(rule.id);
      const changed = prev !== undefined && prev !== res.status;
      const finding: Finding = {
        rule,
        status: res.status,
        affected: res.affected,
        ratio: res.ratio,
        actual: res.actual,
        statusChangeDate: changed ? today : undefined,
      };
      return finding;
    });
}
