// Assembles a normalized OrgSnapshot from a live Salesforce org using only
// read APIs (REST query, Tooling query). Every source is wrapped so a failure
// (missing permission, unsupported field, edition difference) degrades the
// affected checks to "Not Evaluated" instead of a misleading pass.

import { readMetadata, readMetadataMany, readMetadataAll, listMetadata, flatten } from "./metadata.js";

const API_VERSION = "v64.0";

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
  // Some orgs expose the cross-origin headers at the top level rather than under
  // sessionSettings; both spellings map to the same check, whichever is present.
  enableCoepHeader: "malware.coep",
  enableCoopHeader: "malware.coop",
  "sessionSettings.forceLogoutOnSessionTimeout": "access.forceLogoutOnTimeout",
  "sessionSettings.enforceIpRangesEveryRequest": "access.ipEveryRequest",
  "sessionSettings.redirectionWarning": "access.warnRedirect",
  "sessionSettings.enableMFADirectUILoginOptIn": "mfa.allDirectUiLogins",
  "sessionSettings.identityConfirmationOnTwoFactorRegistrationEnabled": "mfa.verifyOnRegistration",
  "singleSignOnSettings.enableSamlLogin": "access.ssoEnabled",
  "passwordPolicies.minimumPasswordLifetime": "pwd.minLifetime",

  // ── Additional org toggles already present in the SecuritySettings payload ──
  enableRequireHttpsConnection: "access.requireHttpsConnection",
  canUsersGrantLoginAccess: "access.usersGrantLoginAccess",
  enableAdminLoginAsAnyUser: "access.adminLoginAsAnyUser",
  enableCrossOrgRedirects: "baseline.crossOrgRedirects",
  redirectBlockModeEnabled: "baseline.redirectBlockMode",
  "sessionSettings.enableCacheAndAutocomplete": "access.cacheAndAutocomplete",
  "sessionSettings.requireHttpOnly": "access.requireHttpOnly",
  "sessionSettings.lockSessionsToDomain": "access.lockSessionsToDomain",
  "sessionSettings.lockSessionsToIp": "access.lockSessionsToIp",
  "sessionSettings.forceRelogin": "access.forceReloginAfterLoginAs",
  "sessionSettings.terminateUserSessionsWhenAdminResetsPassword": "access.terminateSessionsOnPasswordReset",
  "sessionSettings.identityConfirmationOnEmailChange": "access.identityConfirmOnEmailChange",
  "sessionSettings.canConfirmEmailChangeInLightningCommunities": "access.emailChangeConfirmCommunities",
  "sessionSettings.allowUserAuthenticationByCertificate": "access.certificateBasedAuth",
  "sessionSettings.enablePostForSessions": "baseline.postForSessions",
  "singleSignOnSettings.isLoginWithSalesforceCredentialsDisabled": "access.disableLoginWithSfCredentials",
  "sessionSettings.enableU2F": "mfa.securityKeyU2F",
  "sessionSettings.enableSMSIdentity": "mfa.smsIdentityVerification",
  "sessionSettings.enableBuiltInAuthenticator": "mfa.builtInAuthenticator",
  "sessionSettings.enableLightningLogin": "mfa.lightningLogin",
  "passwordPolicies.obscureSecretAnswer": "pwd.obscureSecretAnswer",
};

// Enum-valued SecuritySettings fields kept as raw strings so rules can compare
// them directly (e.g. complexity != "NoRestriction").
const MD_SECURITY_STR: Record<string, string> = {
  "passwordPolicies.complexity": "pwd.complexity",
  "passwordPolicies.questionRestriction": "pwd.questionRestriction",
};

// MyDomainSettings (Metadata API) field → rule setting key.
const MD_MYDOMAIN_BOOL: Record<string, string> = {
  canOnlyLoginWithMyDomainUrl: "access.enforceCustomDomain",
  doesApiLoginRequireOrgDomain: "access.requireMyDomainForApi",
  use3rdPartyCookieBlockingCompatibleHostnames: "access.firstPartyCookies",
  useStabilizedMyDomainHostnames: "access.stabilizedHostnames",
  logRedirections: "access.logRedirections",
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
// (Object-level permissions like Account delete are handled separately below via
// an ObjectPermissions semi-join, not this simple boolean-field pattern.)
const PERMISSION_FIELDS: Record<string, string> = {
  ViewAllData: "PermissionsViewAllData",
  ModifyAllData: "PermissionsModifyAllData",
  ManageUsers: "PermissionsManageUsers",
  BulkApiHardDelete: "PermissionsBulkApiHardDelete",
  WeeklyDataExport: "PermissionsDataExport",
  ViewPII: "PermissionsViewEncryptedData",
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

/**
 * Read one org-settings metadata type (member = type name without the "Settings"
 * suffix, e.g. "Analytics" for AnalyticsSettings) and map its boolean fields to
 * rule setting keys. Returns the flattened record so callers can post-process
 * fields that need custom logic (e.g. negation). Never throws.
 */
async function mapBoolSettings(
  instanceUrl: string,
  token: string,
  type: string,
  member: string,
  boolMap: Record<string, string>,
  settings: Record<string, boolean | number | string>,
  unavailable: { settings: string[] },
  coverage: string[],
  diagnostics: string[]
): Promise<Record<string, string> | null> {
  try {
    const rec = await readMetadata(instanceUrl, token, type, member);
    if (!rec) return null;
    const flat = flatten(rec);
    let mapped = 0;
    for (const [path, key] of Object.entries(boolMap)) {
      if (flat[path] !== undefined) {
        settings[key] = hcBool(flat[path]);
        removeFrom(unavailable.settings, key);
        mapped++;
      }
    }
    coverage.push(`${type}: ${mapped}/${Object.keys(boolMap).length} settings read`);
    return flat;
  } catch (e: any) {
    diagnostics.push(e?.message ?? `Metadata ${type} read failed`);
    return null;
  }
}

// Rule check-keys we know we cannot populate from the read APIs above; these are
// surfaced to the engine as unavailable so they render Not Evaluated.
/** Derived lists that only have meaning once ConnectedApp metadata is readable. */
const CONNECTED_APP_LISTS = [
  "oauthFullScopeApps", "connectedAppsIpRelax", "connectedAppsNonExpiring",
  "connectedAppsNoPkce", "connectedAppsClientCredentials", "connectedAppsPublicClient",
  "connectedAppsIntrospectAll", "connectedAppsRefreshNoSecret",
  "connectedAppsUnrestricted", "connectedAppsNoSingleLogout", "connectedAppsInsecureCallback",
];

/** Derived lists backed by Certificate metadata. */
const CERT_LISTS = [
  "certsExpired", "certsExpiringSoon", "certsWeakKey", "certsSelfSigned", "certsExportableKey",
];

/** XML booleans arrive as real booleans or the strings "true"/"false". */
function mdBool(v: unknown): boolean | undefined {
  if (typeof v === "boolean") return v;
  if (v === "true") return true;
  if (v === "false") return false;
  return undefined;
}

/** A metadata field that may be absent, a single value, or an array. */
function asList(v: unknown): string[] {
  if (v === undefined || v === null || v === "") return [];
  return (Array.isArray(v) ? v : [v]).map((x) => String(x)).filter(Boolean);
}

const UNAVAILABLE = {
  settings: [
    "malware.clickjackVfStandard", "malware.clickjackVfDisabledHeaders", "malware.coep",
    "malware.coop", "malware.contentSniffing", "malware.htmlUploadBlocked",
    "access.remoteSitesAllHttps", "access.ssoEnabled", "access.enforceCustomDomain",
    "access.warnRedirect", "access.requireMyDomainForApi",
    "mfa.allDirectUiLogins", "mfa.verifyOnRegistration", "dlp.dashboardSnapshots",
    "baseline.pimEnhanced", "baseline.guestApiEnabled", "baseline.profileFiltering",
    "audit.eventLogGeneration", "audit.eventLogDeleteDisabled",
    // Session / login / password toggles read from the same settings payloads.
    "access.requireHttpsConnection", "access.usersGrantLoginAccess",
    "access.adminLoginAsAnyUser", "access.cacheAndAutocomplete",
    "access.requireHttpOnly", "access.lockSessionsToDomain", "access.lockSessionsToIp",
    "access.forceReloginAfterLoginAs", "access.terminateSessionsOnPasswordReset",
    "access.identityConfirmOnEmailChange", "access.emailChangeConfirmCommunities",
    "access.certificateBasedAuth", "access.disableLoginWithSfCredentials",
    "access.firstPartyCookies", "access.stabilizedHostnames", "access.logRedirections",
    "mfa.securityKeyU2F", "mfa.smsIdentityVerification", "mfa.builtInAuthenticator",
    "mfa.lightningLogin",
    "baseline.crossOrgRedirects", "baseline.redirectBlockMode", "baseline.postForSessions",
    "baseline.userSelfDeactivate", "baseline.restrictEmailDomains",
    "pwd.obscureSecretAnswer", "pwd.complexity", "pwd.questionRestriction",
    "audit.userFieldHistory",
  ] as string[],
  lists: [
    "objectsPublicExternal", "publicLinksNoPassword",
    ...CONNECTED_APP_LISTS, ...CERT_LISTS,
  ] as string[],
  metrics: ["DeleteAccounts", "ViewPII"] as string[],
};

export async function assembleSnapshot(instanceUrl: string, token: string): Promise<any> {
  const sf = new SfClient(instanceUrl, token);
  const settings: Record<string, boolean | number | string> = {};
  const permissionCounts: Record<string, number> = {};
  const permissionAffected: Record<string, string[]> = {};
  // Informational "what we read" lines, kept separate from sf.diagnostics (which
  // holds only real API failures) so the UI never labels successes as errors.
  const coverage: string[] = [];
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
    for (const r of risks.records) {
      const group = String(r.SettingGroup ?? "");
      const label = String(r.Setting ?? "").toLowerCase();
      const m = HEALTHCHECK_MATCHERS.find(
        (x) => x.group === group && x.all.every((k) => label.includes(k)) && !x.not?.some((k) => label.includes(k))
      );
      if (!m) continue;
      matched++;
      settings[m.key] = m.type === "bool" ? hcBool(r.OrgValue) : hcNum(r.OrgValue);
      const i = unavailable.settings.indexOf(m.key);
      if (i !== -1) unavailable.settings.splice(i, 1);
    }
    coverage.push(`Health Check: ${risks.records.length} risk rows, ${matched} mapped`);
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
      for (const [path, key] of Object.entries(MD_SECURITY_STR)) {
        if (flat[path] !== undefined) { settings[key] = String(flat[path]); removeFrom(unavailable.settings, key); mapped++; }
      }
      coverage.push(`SecuritySettings: ${mapped} settings read`);
    }
  } catch (e: any) {
    sf.diagnostics.push(e?.message ?? "Metadata SecuritySettings read failed");
  }

  // My Domain enforcement toggles (separate settings type).
  try {
    const md = await readMetadata(instanceUrl, token, "MyDomainSettings", "MyDomain");
    if (md) {
      const flat = flatten(md);
      let mapped = 0;
      for (const [path, key] of Object.entries(MD_MYDOMAIN_BOOL)) {
        if (flat[path] !== undefined) { settings[key] = hcBool(flat[path]); removeFrom(unavailable.settings, key); mapped++; }
      }
      coverage.push(`MyDomainSettings: ${mapped} settings read`);
    }
  } catch (e: any) {
    sf.diagnostics.push(e?.message ?? "Metadata MyDomainSettings read failed");
  }

  // Remote Site Settings: every active site must use HTTPS (no relaxed protocol).
  try {
    const names = await listMetadata(instanceUrl, token, "RemoteSiteSetting");
    if (names.length === 0) {
      settings["access.remoteSitesAllHttps"] = true; // none defined → vacuously compliant
      removeFrom(unavailable.settings, "access.remoteSitesAllHttps");
    } else {
      const recs: any[] = [];
      for (let i = 0; i < names.length && i < 60; i += 10) {
        recs.push(...(await readMetadataMany(instanceUrl, token, "RemoteSiteSetting", names.slice(i, i + 10))));
      }
      const insecure = recs.filter(
        (r) => String(r?.isActive) === "true" &&
          (String(r?.url ?? "").toLowerCase().startsWith("http://") || String(r?.disableProtocolSecurity) === "true")
      );
      settings["access.remoteSitesAllHttps"] = insecure.length === 0;
      removeFrom(unavailable.settings, "access.remoteSitesAllHttps");
    }
  } catch (e: any) {
    sf.diagnostics.push(e?.message ?? "Metadata RemoteSiteSetting read failed");
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

  // ── Object-level: users who can delete Accounts (ObjectPermissions join) ────
  // Delete is granted on the object, not as a system permission, so we semi-join
  // permission sets that grant Account delete to their active assignees.
  try {
    const res = await sf.query<any>(
      "SELECT Assignee.Username FROM PermissionSetAssignment " +
      "WHERE Assignee.IsActive = true AND PermissionSetId IN " +
      "(SELECT ParentId FROM ObjectPermissions WHERE SobjectType = 'Account' AND PermissionsDelete = true)"
    );
    const names = Array.from(
      new Set(res.records.map((x: any) => x.Assignee?.Username).filter(Boolean))
    );
    permissionCounts["DeleteAccounts"] = names.length;
    permissionAffected["DeleteAccounts"] = names as string[];
    removeFrom(unavailable.metrics, "DeleteAccounts");
  } catch { /* stays Not Evaluated */ }

  // ── Dashboard component snapshots (Reports & Dashboards) ────────────────────
  await mapBoolSettings(
    instanceUrl, token, "AnalyticsSettings", "Analytics",
    { enableDashboardComponentSnapshot: "dlp.dashboardSnapshots" },
    settings, unavailable, coverage, sf.diagnostics
  );

  // ── User management: Enhanced PIM + guest profile filtering ─────────────────
  await mapBoolSettings(
    instanceUrl, token, "UserManagementSettings", "UserManagement",
    {
      enableEnhancedConcealPersonalInfo: "baseline.pimEnhanced",
      enableProfileFiltering: "baseline.profileFiltering",
      enableUserSelfDeactivate: "baseline.userSelfDeactivate",
      enableRestrictEmailDomains: "baseline.restrictEmailDomains",
      userFieldHistoryTracking: "audit.userFieldHistory",
    },
    settings, unavailable, coverage, sf.diagnostics
  );

  // ── Event Monitoring: log generation + audit-record deletion ────────────────
  // enableEventLogGeneration → generation on. enableDeleteMonitoringData means
  // deletion is *allowed*, so the "deletion disabled" check is its negation.
  {
    const ev = await mapBoolSettings(
      instanceUrl, token, "EventSettings", "Event",
      { enableEventLogGeneration: "audit.eventLogGeneration" },
      settings, unavailable, coverage, sf.diagnostics
    );
    if (ev && ev["enableDeleteMonitoringData"] !== undefined) {
      settings["audit.eventLogDeleteDisabled"] = !hcBool(ev["enableDeleteMonitoringData"]);
      removeFrom(unavailable.settings, "audit.eventLogDeleteDisabled");
    }
  }

  // ── Guest profiles with 'API Enabled' (unauthenticated programmatic access) ──
  try {
    const gp = await sf.query<any>(
      "SELECT Profile.Name FROM PermissionSet " +
      "WHERE IsOwnedByProfile = true AND PermissionsApiEnabled = true AND Profile.UserType = 'Guest'"
    );
    settings["baseline.guestApiEnabled"] = gp.records.length > 0;
    removeFrom(unavailable.settings, "baseline.guestApiEnabled");
  } catch { /* Profile.UserType unsupported here → Not Evaluated */ }

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

  // ── Connected apps: OAuth config + policy (Metadata API) ───────────────────
  // listMetadata gives the app names; readMetadata returns the nested oauthConfig
  // and oauthPolicy that the connected-app checks evaluate. Requires the
  // "Customize Application" / "Manage Connected Apps" permissions.
  const connectedApps: any[] = [];
  try {
    const names = await listMetadata(instanceUrl, token, "ConnectedApp");
    const records = await readMetadataAll(instanceUrl, token, "ConnectedApp", names);
    for (const r of records) {
      if (!r?.fullName) continue;
      const oc = r.oauthConfig ?? {};
      const op = r.oauthPolicy ?? {};
      const profiles = asList(r.profileName);
      const permSets = asList(r.permissionSetName);
      connectedApps.push({
        name: r.label ?? r.fullName,
        scopes: asList(oc.scopes).map((s) => String(s).toLowerCase()),
        ipRelaxation: String(op.ipRelaxation ?? "ENFORCE").toUpperCase() === "RELAX" ? "RELAX" : "ENFORCE",
        usesNonExpiringRefreshTokens: String(op.refreshTokenPolicy ?? "").toLowerCase() === "infinite",
        pkceRequired: mdBool(oc.isPkceRequired),
        clientCredentialsEnabled: mdBool(oc.isClientCredentialEnabled),
        consumerSecretOptional: mdBool(oc.isConsumerSecretOptional),
        introspectAllTokens: mdBool(oc.isIntrospectAllTokens),
        secretRequiredForRefresh: mdBool(oc.isSecretRequiredForRefreshToken),
        restrictedToProfilesOrPermSets: profiles.length > 0 || permSets.length > 0,
        singleLogoutUrl: op.singleLogoutUrl ?? oc.singleLogoutUrl ?? "",
        callbackUrl: oc.callbackUrl ?? "",
      });
    }
    coverage.push(`ConnectedApp: ${connectedApps.length} of ${names.length} apps read`);
    for (const l of CONNECTED_APP_LISTS) removeFrom(unavailable.lists, l);
  } catch (e: any) {
    sf.diagnostics.push(`ConnectedApp metadata: ${String(e?.message ?? e).slice(0, 160)}`);
  }

  // ── Certificates and key pairs (Metadata API) → Key Management domain ──────
  const certificates: any[] = [];
  try {
    const names = await listMetadata(instanceUrl, token, "Certificate");
    const records = await readMetadataAll(instanceUrl, token, "Certificate", names);
    const now = Date.now();
    for (const r of records) {
      if (!r?.fullName) continue;
      const exp = r.expirationDate ? Date.parse(String(r.expirationDate)) : NaN;
      certificates.push({
        name: r.masterLabel ?? r.fullName,
        daysToExpiry: Number.isNaN(exp) ? null : Math.floor((exp - now) / 86_400_000),
        keySize: Number.isFinite(Number(r.keySize)) && Number(r.keySize) > 0 ? Number(r.keySize) : null,
        caSigned: mdBool(r.caSigned) === true,
        privateKeyExportable: mdBool(r.privateKeyExportable) === true,
      });
    }
    coverage.push(`Certificate: ${certificates.length} of ${names.length} certificates read`);
    for (const l of CERT_LISTS) removeFrom(unavailable.lists, l);
  } catch (e: any) {
    sf.diagnostics.push(`Certificate metadata: ${String(e?.message ?? e).slice(0, 160)}`);
  }

  return {
    org,
    settings,
    users,
    permissionCounts,
    permissionAffected,
    connectedApps,
    certificates,
    publicLinksNoPassword,
    objectsPublicExternal,
    guestSharingRules: [],
    healthCheckScore,
    totalActiveUsers,
    unavailable,
    _coverage: coverage,
    _diagnostics: sf.diagnostics,
  };
}
