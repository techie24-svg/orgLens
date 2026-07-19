import { useCallback, useEffect, useMemo, useState } from "react";
import type { Finding, OrgSnapshot, Rule, Status } from "./types";
import { BUILTIN_RULES } from "./rules/catalog";
import { MockProvider } from "./lib/salesforce";
import { runScan } from "./lib/engine";
import { todayLabel } from "./lib/format";
import { getSession, scanLiveOrg, startOAuth, logout as apiLogout } from "./lib/api";

// A seeded "previous scan" so drift (Status change date) is visible on first run.
const SEED_PREVIOUS: Record<string, Status> = {
  "access.sso_enabled": "Passed", // regressed to Failed
  "perm.modify_all_data": "Passed", // regressed to Failed
  "pwd.min_length": "Failed", // improved to Passed
  "audit.event_log_generation": "Failed", // improved to Passed
};

export type Mode = "demo" | "live";

export interface Store {
  connected: boolean;
  mode: Mode;
  scanning: boolean;
  hydrating: boolean;
  error: string | null;
  instanceHost: string | null;
  deployedCommit: string | null;
  snapshot: OrgSnapshot | null;
  findings: Finding[];
  rules: Rule[];
  lastRun: string | null;
  disabledIds: Set<string>;
  runDemo: () => Promise<void>;
  connectLive: (host: string) => void;
  rescan: () => Promise<void>;
  disconnect: () => Promise<void>;
  addCustomRule: (rule: Rule) => void;
  removeCustomRule: (id: string) => void;
  toggleRule: (id: string) => void;
}

function buildRuleset(customRules: Rule[], disabledIds: Set<string>): Rule[] {
  return [...BUILTIN_RULES, ...customRules].map((r) => ({ ...r, enabled: !disabledIds.has(r.id) }));
}

export function useStore(): Store {
  const [connected, setConnected] = useState(false);
  const [mode, setMode] = useState<Mode>("demo");
  const [scanning, setScanning] = useState(false);
  const [hydrating, setHydrating] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [instanceHost, setInstanceHost] = useState<string | null>(null);
  const [deployedCommit, setDeployedCommit] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<OrgSnapshot | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [customRules, setCustomRules] = useState<Rule[]>([]);
  const [disabledIds, setDisabledIds] = useState<Set<string>>(new Set());
  const [lastRun, setLastRun] = useState<string | null>(null);

  const rules = useMemo(() => buildRuleset(customRules, disabledIds), [customRules, disabledIds]);

  const recompute = useCallback((snap: OrgSnapshot, ruleset: Rule[]) => {
    const previous = new Map<string, Status>(Object.entries(SEED_PREVIOUS));
    // Drop checks a scan can't evaluate (data a live org doesn't expose via read
    // APIs) so the results list only ever shows real Passed/Failed outcomes.
    // The mock/demo snapshot is fully populated, so nothing is filtered there.
    const evaluated = runScan(ruleset, snap, previous).filter((f) => f.status !== "Not Evaluated");
    setFindings(evaluated);
    setLastRun(todayLabel());
  }, []);

  const runDemo = useCallback(async () => {
    setError(null);
    setScanning(true);
    const snap = await new MockProvider().fetchSnapshot();
    setSnapshot(snap);
    setMode("demo");
    setInstanceHost(null);
    setConnected(true);
    recompute(snap, buildRuleset(customRules, disabledIds));
    setScanning(false);
  }, [customRules, disabledIds, recompute]);

  const runLiveScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      const snap = await scanLiveOrg();
      setSnapshot(snap);
      setMode("live");
      setConnected(true);
      recompute(snap, buildRuleset(customRules, disabledIds));
    } catch (e: any) {
      setError(e?.message ?? "Live scan failed");
    } finally {
      setScanning(false);
    }
  }, [customRules, disabledIds, recompute]);

  const connectLive = useCallback((host: string) => startOAuth(host), []);

  // On load: surface OAuth errors, then check for an existing live session.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oauthError = params.get("error");
    if (oauthError) setError(decodeURIComponent(oauthError));
    if (params.has("connected") || params.has("error")) {
      window.history.replaceState({}, "", window.location.pathname);
    }
    (async () => {
      const session = await getSession();
      setDeployedCommit(session.deployedCommit ?? null);
      if (session.connected) {
        setInstanceHost(session.instanceHost ?? null);
        await runLiveScan();
      }
      setHydrating(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rescan = useCallback(async () => {
    if (mode === "live") return runLiveScan();
    if (!snapshot) return;
    setScanning(true);
    await new Promise((r) => setTimeout(r, 300));
    recompute(snapshot, buildRuleset(customRules, disabledIds));
    setScanning(false);
  }, [mode, snapshot, customRules, disabledIds, recompute, runLiveScan]);

  const disconnect = useCallback(async () => {
    await apiLogout();
    setConnected(false);
    setSnapshot(null);
    setFindings([]);
    setInstanceHost(null);
    setMode("demo");
    setLastRun(null);
  }, []);

  const addCustomRule = useCallback(
    (rule: Rule) => {
      const nextCustom = [...customRules.filter((r) => r.id !== rule.id), { ...rule, custom: true }];
      setCustomRules(nextCustom);
      if (snapshot) recompute(snapshot, buildRuleset(nextCustom, disabledIds));
    },
    [customRules, disabledIds, snapshot, recompute]
  );

  const removeCustomRule = useCallback(
    (id: string) => {
      const nextCustom = customRules.filter((r) => r.id !== id);
      setCustomRules(nextCustom);
      if (snapshot) recompute(snapshot, buildRuleset(nextCustom, disabledIds));
    },
    [customRules, disabledIds, snapshot, recompute]
  );

  const toggleRule = useCallback(
    (id: string) => {
      const next = new Set(disabledIds);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      setDisabledIds(next);
      if (snapshot) recompute(snapshot, buildRuleset(customRules, next));
    },
    [disabledIds, customRules, snapshot, recompute]
  );

  return {
    connected, mode, scanning, hydrating, error, instanceHost, deployedCommit, snapshot, findings, rules, lastRun, disabledIds,
    runDemo, connectLive, rescan, disconnect, addCustomRule, removeCustomRule, toggleRule,
  };
}
