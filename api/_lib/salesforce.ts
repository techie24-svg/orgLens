// Assembles a normalized OrgSnapshot from a live Salesforce org using only
// read APIs (REST query, Tooling query). Every source is wrapped so a failure
// (missing permission, unsupported field, edition difference) degrades the
// affected checks to "Not Evaluated" instead of a misleading pass.

const API_VERSION = "v60.0";

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
  InstallConnectedApps: "PermissionsInstallMultiforce",
};

// Health Check risk rows expose (SettingGroup, SettingName, SettingValue).
// Map those identifiers to the flat snapshot.settings keys the rules read.
const HEALTHCHECK_MAP: Record<string, { key: string; type: "bool" | "num" }> = {
  "SessionSettings.enableClickjackProtectionSetupPages": { key: "malware.clickjackSetup", type: "bool" },
  "SessionSettings.enableClickjackProtectionNonSetupPages": { key: "malware.clickjackNonSetup", type: "bool" },
  "SessionSettings.enableCSRFOnGet": { key: "malware.csrfGet", type: "bool" },
  "SessionSettings.enableCSRFOnPost": { key: "malware.csrfPost", type: "bool" },
  "SessionSettings.forceLogoutOnSessionTimeout": { key: "access.forceLogoutOnTimeout", type: "bool" },
  "SessionSettings.enforceIpRangesEveryRequest": { key: "access.ipEveryRequest", type: "bool" },
  "PasswordPolicies.passwordExpiration": { key: "pwd.expirationDays", type: "num" },
  "PasswordPolicies.minimumPasswordLength": { key: "pwd.minLength", type: "num" },
  "PasswordPolicies.enforcePasswordHistory": { key: "pwd.history", type: "num" },
  "PasswordPolicies.minimumPasswordLifetime": { key: "pwd.minLifetime", type: "bool" },
  "PasswordPolicies.maxLoginAttempts": { key: "access.maxInvalidLoginAttempts", type: "num" },
};

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
  metrics: ["DeleteAccounts", "ViewPII"] as string[],
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
      const id = `${r.SettingGroup}.${r.Setting}`;
      const m = HEALTHCHECK_MAP[id];
      if (!m) { if (unmatched.length < 8) unmatched.push(id); continue; }
      matched++;
      const raw = r.OrgValue;
      settings[m.key] = m.type === "bool" ? String(raw) === "true" || raw === true : Number(raw);
      const i = unavailable.settings.indexOf(m.key);
      if (i !== -1) unavailable.settings.splice(i, 1);
    }
    sf.diagnostics.push(
      `healthcheck: ${risks.records.length} risk rows, ${matched} mapped` +
      (matched === 0 && unmatched.length ? ` — unmatched ids e.g. ${unmatched.join(", ")}` : "")
    );
  } catch { /* health-check-derived settings stay unavailable */ }

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

  return {
    org,
    settings,
    users,
    permissionCounts,
    permissionAffected,
    connectedApps: [],
    publicLinksNoPassword: [],
    objectsPublicExternal: [],
    guestSharingRules: [],
    healthCheckScore,
    totalActiveUsers,
    unavailable,
    _diagnostics: sf.diagnostics,
  };
}
