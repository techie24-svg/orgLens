// Assembles a normalized OrgSnapshot from a live Salesforce org using only
// read APIs (REST query, Tooling query). Every source is wrapped so a failure
// (missing permission, unsupported field, edition difference) degrades the
// affected checks to "Not Evaluated" instead of a misleading pass.

import { readMetadata, flatten } from "./metadata.js";

const API_VERSION = "v60.0";

// SecuritySettings (Metadata API) flattened-path → rule setting key. These are
// org config toggles that Health Check / SOQL do not expose.
const MD_SECURITY_BOOL: Record<string, string> = {
  "sessionSettings.enableClickjackSetup": "malware.clickjackSetup",
  "sessionSettings.enableClickjackNonsetupSFDC": "malware.clickjackNonSetup",
  "sessionSettings.enableClickjackNonsetupUser": "malware.clickjackVfStandard",
  "sessionSettings.enableClickjackNonsetupUserHeaderless": "malware.clickjackVfDisabledHeaders",
  "sessionSettings.enableCSRFOnGet": "malware.csrfGet",
  "sessionSettings.enableCSRFOnPost": "malware.csrfPost",
  "sessionSettings.enableContentSniffingProtection": "malware.contentSniffing",
  "sessionSettings.enableCoepHeader": "malware.coep",
  "sessionSettings.enableCoopHeader": "malware.coop",
  "sessionSettings.forceLogoutOnSessionTimeout": "access.forceLogoutOnTimeout",
  "sessionSettings.enforceIpRangesEveryRequest": "access.ipEveryRequest",
  "sessionSettings.redirectBlockModeEnabled": "access.warnRedirect",
  "sessionSettings.enableMFADirectUILoginOptIn": "mfa.allDirectUiLogins",
  "sessionSettings.identityConfirmationOnTwoFactorRegistrationEnabled": "mfa.verifyOnRegistration",
  "passwordPolicies.minimumPasswordLifetime": "pwd.minLifetime",
};
const MD_SECURITY_NUM: Record<string, string> = {
  "passwordPolicies.minimumPasswordLength": "pwd.minLength",
  "passwordPolicies.historyRestriction": "pwd.history",
  "passwordPolicies.maxLoginAttempts": "access.maxInvalidLoginAttempts",
  "passwordPolicies.expiration": "pwd.expirationDays",
};

interface QueryResult<T> {
  totalSize: number;
  done: boolean;
  records: T[];
}

class SfClient {
  /** Human-readable record of every failed API call, surfaced for troubleshooting. */
  readonly diagnostics: string[] = [];

  constructor(private instanceUrl: string, private token: string) {}

  private async get(path: string): Promise<any> {
    const res = await fetch(`${this.instanceUrl}${path}`, {
      headers: { Authorization: `Bearer ${this.token}`, Accept: "application/json" },
    });
    if (!res.ok) {
      const text = await res.text();
      const short = path.split("?")[0];
      this.diagnostics.push(`${res.status} ${short}: ${text.slice(0, 200)}`);
      throw new Error(`SF ${res.status} ${path}: ${text.slice(0, 300)}`);
    }
    return res.json();
  }

  query<T = any>(soql: string): Promise<QueryResult<T>> {
    return this.get(`/services/data/${API_VERSION}/query/?q=${encodeURIComponent(soql)}`);
  }

  toolingQuery<T = any>(soql: string): Promise<QueryResult<T>> {
    return this.get(`/services/data/${API_VERSION}/tooling/query/?q=${encodeURIComponent(soql)}`);
  }
}

// System-permission checks that map cleanly to a PermissionSet boolean field.
// (Object-level permissions like Account delete are intentionally omitted —
// they require an ObjectPermissions join and are left Not Evaluated for now.)
const PERMISSION_FIELDS: Record<string, string> = {
  ViewAllData: "PermissionsViewAllData",
  ModifyAllData: "PermissionsModifyAllData",
  ManageUsers: "PermissionsManageUsers",
  BulkApiHardDelete: "PermissionsBulkApiHardDelete",
  WeeklyDataExport: "PermissionsDataExport",
  // NOTE: "Install Connected Apps" has no clean, queryable PermissionSet column
  // (PermissionsInstallMultiforce does not exist on modern orgs), so it is left
  // in UNAVAILABLE.metrics → reported "Not Evaluated" rather than crashing.
};

// SecurityHealthCheckRisks.Setting is a localized *display label*, not an API
// name, and SettingGroup is the section. We match on those labels (lowercased,
// substring) to the flat snapshot.settings keys the rules read. `not` fragments
// disambiguate near-duplicate labels (e.g. Setup vs non-Setup vs Visualforce).
type HcMatcher = { key: string; group: string; all: string[]; not?: string[]; type: "bool" | "num" };
const HEALTHCHECK_MATCHERS: HcMatcher[] = [
  { key: "malware.clickjackSetup", group: "SessionSettings", all: ["clickjack", "setup pages"], not: ["non-setup", "visualforce"], type: "bool" },
  { key: "malware.clickjackNonSetup", group: "SessionSettings", all: ["clickjack", "non-setup"], type: "bool" },
  { key: "malware.clickjackVfStandard", group: "SessionSettings", all: ["clickjack", "visualforce", "standard headers"], type: "bool" },
  { key: "malware.clickjackVfDisabledHeaders", group: "SessionSettings", all: ["clickjack", "visualforce", "headers disabled"], type: "bool" },
  { key: "malware.csrfGet", group: "SessionSettings", all: ["csrf", "get request"], type: "bool" },
  { key: "malware.csrfPost", group: "SessionSettings", all: ["csrf", "post request"], type: "bool" },
  { key: "access.forceLogoutOnTimeout", group: "SessionSettings", all: ["force logout"], type: "bool" },
  { key: "access.ipEveryRequest", group: "SessionSettings", all: ["login ip ranges on every request"], type: "bool" },
  { key: "access.maxInvalidLoginAttempts", group: "PasswordPolicies", all: ["maximum invalid login attempts"], type: "num" },
  { key: "pwd.expirationDays", group: "PasswordPolicies", all: ["passwords expire"], type: "num" },
  { key: "pwd.minLength", group: "PasswordPolicies", all: ["minimum password length"], type: "num" },
  { key: "pwd.history", group: "PasswordPolicies", all: ["password history"], type: "num" },
  { key: "pwd.minLifetime", group: "PasswordPolicies", all: ["password lifetime"], type: "bool" },
];

function removeFrom(list: string[], value: string): void {
  const i = list.indexOf(value);
  if (i !== -1) list.splice(i, 1);
}

function hcBool(raw: unknown): boolean {
  const s = String(raw).trim().toLowerCase();
  return s === "true" || s === "1" || s === "enabled" || s === "yes" || s === "on";
}

/** Health Check numeric OrgValues are display strings ("90 days", "No limit"). */
function hcNum(raw: unknown): number {
  const s = String(raw).trim().toLowerCase();
  if (/no limit|never|none|not enforced|disabled/.test(s)) return 0;
  const m = s.match(/-?\d+/);
  return m ? Number(m[0]) : 0;
}

/**
 * Metadata numeric fields are often enums ("Never", "TenAttempts", "NinetyDays").
 * Map "off"-style values to 0; spelled-out enums that mean "a limit is set" to a
 * nonzero sentinel; plain integers to their value.
 */
function mdNum(raw: unknown): number {
  const s = String(raw).trim().toLowerCase();
  if (!s || /no ?limit|never|none|not ?enforced|zero/.test(s)) return 0;
  const m = s.match(/\d+/);
  return m ? Number(m[0]) : 1;
}

// Rule check-keys we know we cannot populate from the read APIs above; these are
// surfaced to the engine as unavailable so they render Not Evaluated.
const UNAVAILABLE = {
  settings: [
    "malware.clickjackVfStandard", "malware.clickjackVfDisabledHeaders", "malware.coep",
    "malware.coop", "malware.contentSniffing", "malware.htmlUploadBlocked",
    "access.remoteSitesAllHttps", "access.ssoEnabled", "access.enforceCustomDomain",
    "access.connectedAppAllowlist", "access.warnRedirect", "access.requireMyDomainForApi",
    "mfa.allDirectUiLogins", "mfa.verifyOnRegistration", "dlp.dashboardSnapshots",
    "dlp.publicLinksEnabled", "dlp.contentDeliveryPasswordDefault", "baseline.pimEnhanced",
    "baseline.guestApiEnabled", "baseline.profileFiltering", "baseline.canvasNonAdminInstall",
    "audit.eventLogGeneration", "audit.eventLogDeleteDisabled", "privacy.scramblePersonalData",
  ] as string[],
  lists: [
    "oauthFullScopeApps", "connectedAppsIpRelax", "connectedAppsNonExpiring",
    "objectsPublicExternal", "publicLinksNoPassword", "guestSharingRules",
  ] as string[],
  metrics: ["DeleteAccounts", "ViewPII", "InstallConnectedApps"] as string[],
};

export async function assembleSnapshot(instanceUrl: string, token: string): Promise<any> {
  const sf = new SfClient(instanceUrl, token);
  const settings: Record<string, boolean | number | string> = {};
  const permissionCounts: Record<string, number> = {};
  const permissionAffected: Record<string, string[]> = {};
  const unavailable = {
    settings: [...UNAVAILABLE.settings],
    lists: [...UNAVAILABLE.lists],
    metrics: [...UNAVAILABLE.metrics],
  };

  // ── Org info ──────────────────────────────────────────────────────────────
  let org = { alias: "Connected org", orgDomain: instanceUrl, instanceType: "Production" as "Production" | "Sandbox", businessOwner: "—" };
  try {
    const r = await sf.query<any>("SELECT Name, OrganizationType, IsSandbox, InstanceName FROM Organization LIMIT 1");
    const o = r.records[0];
    if (o) {
      org = {
        alias: o.Name ?? "Connected org",
        orgDomain: new URL(instanceUrl).host,
        instanceType: o.IsSandbox ? "Sandbox" : "Production",
        businessOwner: o.OrganizationType ?? "—",
      };
    }
  } catch { /* keep defaults */ }

  // ── Users: active count + dormant list ─────────────────────────────────────
  let totalActiveUsers = 0;
  const users: { username: string; isActive: boolean; lastLoginDays: number | null }[] = [];
  try {
    const countRes = await sf.query<any>("SELECT COUNT(Id) total FROM User WHERE IsActive = true");
    totalActiveUsers = countRes.records[0]?.total ?? countRes.totalSize ?? 0;
    const cutoff = new Date(Date.now() - 90 * 864e5).toISOString();
    const dormant = await sf.query<any>(
      `SELECT Username, LastLoginDate FROM User WHERE IsActive = true AND (LastLoginDate = null OR LastLoginDate < ${cutoff}) LIMIT 200`
    );
    for (const u of dormant.records) {
      const days = u.LastLoginDate ? Math.floor((Date.now() - new Date(u.LastLoginDate).getTime()) / 864e5) : null;
      users.push({ username: u.Username, isActive: true, lastLoginDays: days });
    }
  } catch { /* leave zero */ }

  // ── Health Check score + risk-derived settings ─────────────────────────────
  let healthCheckScore = 0;
  try {
    const hc = await sf.toolingQuery<any>("SELECT Score FROM SecurityHealthCheck");
    healthCheckScore = Math.round(hc.records[0]?.Score ?? 0);
  } catch { /* leave zero */ }
  try {
    const risks = await sf.toolingQuery<any>(
      "SELECT SettingGroup, Setting, OrgValue FROM SecurityHealthCheckRisks"
    );
    let matched = 0;
    const unmatched: string[] = [];
    for (const r of risks.records) {
      const group = String(r.SettingGroup ?? "");
      const label = String(r.Setting ?? "").toLowerCase();
      const m = HEALTHCHECK_MATCHERS.find(
        (x) => x.group === group && x.all.every((k) => label.includes(k)) && !x.not?.some((k) => label.includes(k))
      );
      if (!m) { if (unmatched.length < 12) unmatched.push(`${group}.${r.Setting}`); continue; }
      matched++;
      settings[m.key] = m.type === "bool" ? hcBool(r.OrgValue) : hcNum(r.OrgValue);
      const i = unavailable.settings.indexOf(m.key);
      if (i !== -1) unavailable.settings.splice(i, 1);
    }
    sf.diagnostics.push(
      `healthcheck: ${risks.records.length} risk rows, ${matched} mapped` +
      (matched < HEALTHCHECK_MATCHERS.length && unmatched.length ? ` — still unmatched e.g. ${unmatched.join(" | ")}` : "")
    );
  } catch { /* health-check-derived settings stay unavailable */ }

  // ── Metadata API: org security/session/file-upload toggles ──────────────────
  try {
    const sec = await readMetadata(instanceUrl, token, "SecuritySettings", "Security");
    if (sec) {
      const flat = flatten(sec);
      let mapped = 0;
      for (const [path, key] of Object.entries(MD_SECURITY_BOOL)) {
        if (flat[path] !== undefined) { settings[key] = hcBool(flat[path]); removeFrom(unavailable.settings, key); mapped++; }
      }
      for (const [path, key] of Object.entries(MD_SECURITY_NUM)) {
        if (flat[path] !== undefined) { settings[key] = mdNum(flat[path]); removeFrom(unavailable.settings, key); mapped++; }
      }
      // Surface security-relevant keys we don't yet map (e.g. COEP/COOP/CSP), to
      // guide follow-up mapping without another blind guess.
      const hints = Object.keys(flat)
        .filter((k) => /coep|coop|cross|csp|referrer|sniff|redirect|mfa|sso|https|httponly/i.test(k))
        .slice(0, 14);
      sf.diagnostics.push(`metadata SecuritySettings: ${mapped} mapped; security keys: ${hints.join(", ") || "none"}`);
    }
  } catch (e: any) {
    sf.diagnostics.push(e?.message ?? "Metadata SecuritySettings read failed");
  }

  // HTML-file-upload behavior lives in a separate settings type.
  try {
    const fu = await readMetadata(instanceUrl, token, "FileUploadAndDownloadSecuritySettings", "FileUploadAndDownloadSecurity");
    const raw = fu?.dispositions;
    const dispositions: any[] = Array.isArray(raw) ? raw : raw ? [raw] : [];
    if (dispositions.length) {
      const html = dispositions.find((d) => /html/i.test(String(d?.securityRiskFileType ?? "")));
      if (html) {
        settings["malware.htmlUploadBlocked"] = String(html.behavior).toUpperCase() === "DOWNLOAD";
        removeFrom(unavailable.settings, "malware.htmlUploadBlocked");
      }
    }
  } catch (e: any) {
    sf.diagnostics.push(e?.message ?? "Metadata FileUpload read failed");
  }

  // ── Permission counts (distinct active assignees per system permission) ─────
  await Promise.all(
    Object.entries(PERMISSION_FIELDS).map(async ([metric, field]) => {
      try {
        const res = await sf.query<any>(
          `SELECT Assignee.Username FROM PermissionSetAssignment ` +
          `WHERE PermissionSet.${field} = true AND Assignee.IsActive = true`
        );
        const names = Array.from(
          new Set(res.records.map((x: any) => x.Assignee?.Username).filter(Boolean))
        );
        permissionCounts[metric] = names.length;
        permissionAffected[metric] = names as string[];
      } catch {
        unavailable.metrics.push(metric); // field unsupported in this edition → Not Evaluated
      }
    })
  );

  // ── Public file links / content deliveries missing a password (SOQL) ────────
  const publicLinksNoPassword: string[] = [];
  try {
    const cd = await sf.query<any>(
      "SELECT Name FROM ContentDistribution WHERE PreferencesPasswordRequired = false LIMIT 200"
    );
    for (const r of cd.records) publicLinksNoPassword.push(r.Name ?? "(unnamed delivery)");
    removeFrom(unavailable.lists, "publicLinksNoPassword");
  } catch { /* stays unavailable → Not Evaluated */ }

  // ── Objects whose external org-wide default is Public (Tooling) ─────────────
  const objectsPublicExternal: string[] = [];
  try {
    const ed = await sf.toolingQuery<any>(
      "SELECT QualifiedApiName, ExternalSharingModel FROM EntityDefinition " +
      "WHERE ExternalSharingModel IN ('Read','ReadWrite','FullAccess') LIMIT 500"
    );
    for (const r of ed.records) objectsPublicExternal.push(r.QualifiedApiName);
    removeFrom(unavailable.lists, "objectsPublicExternal");
  } catch { /* stays unavailable → Not Evaluated */ }

  return {
    org,
    settings,
    users,
    permissionCounts,
    permissionAffected,
    connectedApps: [],
    publicLinksNoPassword,
    objectsPublicExternal,
    guestSharingRules: [],
    healthCheckScore,
    totalActiveUsers,
    unavailable,
    _diagnostics: sf.diagnostics,
  };
}
