/**
 * Dev sanity check: every rule has a unique id, and the demo snapshot evaluates
 * each one to a real status (never "Not Evaluated", which would mean the demo
 * data is missing an input the rule depends on).
 */
import { BUILTIN_RULES as CATALOG } from "../src/rules/catalog";
import { SAMPLE_ORG } from "../src/data/sampleOrg";
import { evaluateRule } from "../src/lib/engine";

const ids = CATALOG.map((r) => r.id);
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);

const byStatus: Record<string, string[]> = {};
const byDomain: Record<string, number> = {};
for (const rule of CATALOG) {
  const { status } = evaluateRule(rule, SAMPLE_ORG as any);
  (byStatus[status] ??= []).push(rule.id);
  byDomain[rule.domain] = (byDomain[rule.domain] ?? 0) + 1;
}

console.log(`rules: ${CATALOG.length}`);
console.log(`duplicate ids: ${dupes.length ? dupes.join(", ") : "none"}`);
console.log("\nby domain:");
for (const [d, n] of Object.entries(byDomain).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(n).padStart(3)}  ${d}`);
}
console.log("\nby demo status:");
for (const [s, list] of Object.entries(byStatus)) console.log(`  ${String(list.length).padStart(3)}  ${s}`);

const notEvaluated = byStatus["Not Evaluated"] ?? [];
if (notEvaluated.length) console.log(`\nNot Evaluated in demo (demo data gap):\n  ${notEvaluated.join("\n  ")}`);
if (dupes.length || notEvaluated.length) process.exit(1);
