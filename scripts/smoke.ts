import { BUILTIN_RULES } from "../src/rules/catalog";
import { SAMPLE_ORG } from "../src/data/sampleOrg";
import { runScan } from "../src/lib/engine";
import { rollup } from "../src/lib/score";
import { complianceRollup } from "../src/lib/compliance";
import { toCsv } from "../src/lib/report";

const rules = BUILTIN_RULES.map((r) => ({ ...r, enabled: true }));
const previous = new Map<string, any>([
  ["access.sso_enabled", "Passed"],
  ["perm.modify_all_data", "Passed"],
  ["pwd.min_length", "Failed"],
  ["audit.event_log_generation", "Failed"],
]);
const findings = runScan(rules, SAMPLE_ORG, previous);
const r = rollup(findings);

console.log("Total checks:", findings.length);
console.log("Passed / Failed / NotEval:", r.passed, r.failed, r.notEval);
console.log("Posture score:", Math.round(r.score));
console.log("Drift (changed):", findings.filter((f) => f.statusChangeDate).length);
console.log("Not-evaluated rules:", findings.filter((f) => f.status === "Not Evaluated").map((f) => f.rule.id));
console.log("\nBy severity:", JSON.stringify(r.bySeverity));
console.log("\nDomains (worst first):");
r.byDomain.forEach((d) => console.log(`  ${d.domain}: ${d.passed}/${d.passed + d.failed} (${Math.round(d.score)}%)`));
console.log("\nCompliance:");
complianceRollup(findings).forEach((c) => console.log(`  ${c.label}: mapped ${c.mapped}, failed ${c.failed}, controls ${c.failingControls.length}`));

const csv = toCsv(findings, SAMPLE_ORG);
const lines = csv.split("\r\n");
console.log("\nCSV columns:", lines[0].split(",").length);
console.log("CSV rows:", lines.length - 1);
