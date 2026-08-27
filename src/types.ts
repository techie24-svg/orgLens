// Core domain types for OrgLens.

export type Severity = "High" | "Medium" | "Low";
export type Status = "Passed" | "Failed" | "Not Evaluated";
export type Op = "==" | "!=" | "<=" | ">=" | "<" | ">";

/** The six compliance frameworks OrgLens maps every check to. */
export interface Compliance {
  ISO_27001_2022?: string[];
  NIST_800_53?: string[];
  SOC2?: string[];
  CSA_CCM?: string[];
  PCI_DSS_4?: string[];
  NIST_CSF_2?: string[];
}

export const FRAMEWORKS: { key: keyof Compliance; label: string; column: string }[] = [
  { key: "ISO_27001_2022", label: "ISO/IEC 27001:2022", column: "ISO/IEC 27001 2022" },
  { key: "NIST_800_53", label: "NIST SP 800-53 Rev. 5", column: "NIST SP 800-53 Rev. 5" },
  { key: "SOC2", label: "SOC 2 Type 2", column: "SOC 2 TYPE 2" },
  { key: "CSA_CCM", label: "CSA Cloud Controls Matrix", column: "Cloud Security Alliance  - Cloud Controls Matrix" },
  { key: "PCI_DSS_4", label: "PCI-DSS 4.0", column: "Payment Card Industry Data Security Standard (PCI-DSS) 4.0" },
  { key: "NIST_CSF_2", label: "NIST CSF 2.0", column: "NIST CSF 2.0" },
];

/**
 * A declarative check. Built-in and user-authored rules share this shape, so
 * adding a rule never requires a code change (see DESIGN.md §3.2).
 */
export interface CheckSpec {
  /** How the value is fetched from the org. */
  source: "healthcheck" | "metadata" | "soql";
  /**
   * - setting:   probe a config `path`, compare with `op` to `value`
   * - count:     resolve a `metric`, compare with `op` to `threshold`
   * - listEmpty: resolve a `list`, pass when it is empty (offenders are `Affected`)
   */
  kind: "setting" | "count" | "listEmpty";
  path?: string;
  op?: Op;
  value?: boolean | number | string;
  metric?: string;
  threshold?: number;
  list?: string;
}

export interface Rule {
  id: string;
  domain: string;
  severity: Severity;
  title: string;
  description: string;
  info: string;
  remediation: string;
  check: CheckSpec;
  compliance: Compliance;
  tags?: string[];
  enabled?: boolean;
  custom?: boolean;
}

/** Result of evaluating one rule against an org snapshot. */
export interface Finding {
  rule: Rule;
  status: Status;
  /** Human-readable "who/what is affected" (kept as text, per report parity). */
  affected: string;
  /** e.g. "7/63" active users — stored as text to avoid spreadsheet date coercion. */
  ratio: string;
  actual: string;
  statusChangeDate?: string;
}

export interface OrgUser {
  username: string;
  isActive: boolean;
  lastLoginDays: number | null;
}

export interface ConnectedApp {
  name: string;
  scopes: string[];
  ipRelaxation: "ENFORCE" | "RELAX";
  usesNonExpiringRefreshTokens: boolean;
  /** oauthConfig.isPkceRequired — PKCE hardens the authorization-code flow. */
  pkceRequired?: boolean;
  /** oauthConfig.isClientCredentialEnabled — machine-to-machine flow, no user context. */
  clientCredentialsEnabled?: boolean;
  /** oauthConfig.isConsumerSecretOptional — a public client anyone can impersonate. */
  consumerSecretOptional?: boolean;
  /** oauthConfig.isIntrospectAllTokens — lets the app introspect tokens it does not own. */
  introspectAllTokens?: boolean;
  /** oauthConfig.isSecretRequiredForRefreshToken */
  secretRequiredForRefresh?: boolean;
  /** True when access is restricted to named profiles or permission sets. */
  restrictedToProfilesOrPermSets?: boolean;
  singleLogoutUrl?: string;
  callbackUrl?: string;
}

/**
 * An External Client App — the successor to Connected Apps. Its OAuth config is
 * split across ExtlClntAppGlobalOauthSettings (credential handling) and
 * ExtlClntAppOauthConfigurablePolicies (runtime policy); this is the merged view.
 */
export interface ExternalClientApp {
  name: string;
  pkceRequired?: boolean;
  refreshTokenRotation?: boolean;
  secretRequiredForRefresh?: boolean;
  consumerSecretOptional?: boolean;
  introspectAllTokens?: boolean;
  callbackUrl?: string;
  ipRelaxation?: "ENFORCE" | "RELAX";
  clientCredentialsEnabled?: boolean;
  tokenExchangeEnabled?: boolean;
  /** "AdminApprovedPreAuthorized" | "AllSelfAuthorized" */
  permittedUsers?: string;
  /** "Infinite" | "SpecificInactivity" | "SpecificLifetime" | "Zero" */
  refreshTokenPolicy?: string;
  /** Validity normalized to days, regardless of the unit the org stored. */
  refreshTokenValidityDays?: number | null;
  /** "STANDARD" | "HIGH_ASSURANCE" */
  requiredSessionLevel?: string;
}

/**
 * A profile that overrides the org-wide session or password policy. These
 * components exist only when a profile deviates from the org default, so an
 * absent profile is inheriting the org settings checked by the `access.*` and
 * `pwd.*` rules.
 */
export interface ProfilePolicyOverride {
  profile: string;
  /** Minutes of inactivity before logout. */
  sessionTimeout?: number | null;
  /** "STANDARD" | "HIGH_ASSURANCE" */
  requiredSessionLevel?: string;
  /** Days until passwords expire; 0 means never. */
  passwordExpiration?: number | null;
  /** 0 = no restriction, 1 = alphanumeric, 2+ = stronger character classes. */
  passwordComplexity?: number | null;
  /** 1 = hint answer cannot contain the password, 0 = unrestricted. */
  passwordQuestion?: number | null;
  /** Lockout duration in minutes. */
  lockoutInterval?: number | null;
}

/** An org certificate / key pair used for signing, mTLS or SSO. */
export interface OrgCertificate {
  name: string;
  /** Days until expiry; negative when already expired, null when unknown. */
  daysToExpiry: number | null;
  keySize: number | null;
  caSigned: boolean;
  privateKeyExportable: boolean;
}

/**
 * Normalized org data as returned by the connection layer. In production this is
 * assembled from Health Check + Tooling + Metadata + SOQL; in the demo it is
 * produced by the MockProvider.
 */
export interface OrgSnapshot {
  org: {
    alias: string;
    orgDomain: string;
    instanceType: "Production" | "Sandbox";
    businessOwner: string;
  };
  /** Flat, dot-addressable config values (session/password/security settings). */
  settings: Record<string, boolean | number | string>;
  users: OrgUser[];
  /** Active-user count holding a given permission (keyed by permission label). */
  permissionCounts: Record<string, number>;
  /** Offending usernames per permission, for the Affected column. */
  permissionAffected: Record<string, string[]>;
  connectedApps: ConnectedApp[];
  /** External Client Apps (the Connected App successor). */
  externalClientApps: ExternalClientApp[];
  /** Profiles overriding the org-wide session or password policy. */
  profilePolicies: ProfilePolicyOverride[];
  /** Report folders whose access type is Public (visible to all users). */
  publicReportFolders: string[];
  /** Dashboard folders whose access type is Public. */
  publicDashboardFolders: string[];
  /** Org certificates and key pairs, for the Key Management domain. */
  certificates: OrgCertificate[];
  /** Public content-distribution links missing a password. */
  publicLinksNoPassword: string[];
  /** Objects whose org-wide default external access is Public. */
  objectsPublicExternal: string[];
  /** Guest/community sharing rules that expose data. */
  guestSharingRules: string[];
  /** Native Health Check score (0-100), reused as the baseline posture score. */
  healthCheckScore: number;
  totalActiveUsers: number;
  /**
   * Data a live scan could not retrieve (edition/permission/API limits). Checks
   * whose input is listed here are reported "Not Evaluated" rather than a
   * misleading pass. Absent for the fully-populated sample org.
   */
  unavailable?: {
    settings?: string[];
    lists?: string[];
    metrics?: string[];
  };
  /** Informational "what the scan read" lines (successful coverage, not errors). */
  _coverage?: string[];
  /** Live-scan API failures (status + endpoint + message), for troubleshooting. */
  _diagnostics?: string[];
}
