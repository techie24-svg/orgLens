// Bundled sample org snapshot. Mirrors the shape the connection layer returns from
// a live org, seeded to reproduce a realistic mix of pass/fail like the reference
// Falcon Shield report for "PLADS - SANDBOX TEST".

import type { OrgSnapshot } from "../types";

const FIRST = ["Taylor", "Jordan", "Morgan", "Casey", "Riley", "Avery", "Quinn", "Devon", "Reese", "Skyler", "Cameron", "Hayden", "Emerson", "Rowan", "Sawyer", "Parker", "Drew", "Blake", "Elliot", "Finley", "Harper", "Kendall"];
const LAST = ["Parker", "Nguyen", "Patel", "Garcia", "Kim", "Silva", "Cohen", "Okafor", "Rossi", "Haddad", "Novak", "Meyer", "Torres", "Walsh", "Ivanov", "Chen", "Ali", "Brooks", "Diaz", "Reyes", "Ford", "Grant"];

function usernames(n: number, seed: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const f = FIRST[(seed + i * 7) % FIRST.length];
    const l = LAST[(seed * 3 + i * 5) % LAST.length];
    out.push(`${f.toLowerCase()}.${l.toLowerCase()}@plads.example.com`);
  }
  return out;
}

const TOTAL_ACTIVE = 63;

const permissionAffected = {
  ViewAllData: usernames(22, 1),
  ModifyAllData: usernames(18, 5),
  ManageUsers: usernames(12, 9),
  BulkApiHardDelete: usernames(20, 3),
  WeeklyDataExport: usernames(19, 11),
  SuperUser: usernames(9, 2),
  DeleteAccounts: usernames(7, 6),
  ViewPII: usernames(3, 8),
  InstallConnectedApps: usernames(4, 4),
};

const permissionCounts = Object.fromEntries(
  Object.entries(permissionAffected).map(([k, v]) => [k, v.length])
) as Record<string, number>;

export const SAMPLE_ORG: OrgSnapshot = {
  org: {
    alias: "PLADS - SANDBOX TEST",
    orgDomain: "plads--sandbox.sandbox.my.salesforce.com",
    instanceType: "Sandbox",
    businessOwner: "TParker (tparker@plads.example.com)",
  },
  totalActiveUsers: TOTAL_ACTIVE,
  healthCheckScore: 55,
  settings: {
    // Malware Protection (mostly on by default)
    "malware.clickjackSetup": true,
    "malware.clickjackNonSetup": true,
    "malware.clickjackVfStandard": true,
    "malware.clickjackVfDisabledHeaders": true,
    "malware.csrfGet": true,
    "malware.csrfPost": true,
    "malware.coep": false,
    "malware.coop": false,
    "malware.contentSniffing": true,
    "malware.htmlUploadBlocked": true,
    // Access Control
    "access.maxInvalidLoginAttempts": 10,
    "access.remoteSitesAllHttps": true,
    "access.ssoEnabled": false,
    "access.enforceCustomDomain": false,
    "access.forceLogoutOnTimeout": true,
    "access.ipEveryRequest": true,
    "access.warnRedirect": false,
    "access.requireMyDomainForApi": false,
    "access.requireHttpsConnection": true,
    "access.disableLoginWithSfCredentials": false,
    "access.requireHttpOnly": true,
    "access.lockSessionsToDomain": true,
    "access.lockSessionsToIp": false,
    "access.forceReloginAfterLoginAs": true,
    "access.terminateSessionsOnPasswordReset": false,
    "access.identityConfirmOnEmailChange": false,
    "access.emailChangeConfirmCommunities": false,
    "access.certificateBasedAuth": false,
    "access.cacheAndAutocomplete": true,
    "access.usersGrantLoginAccess": true,
    "access.adminLoginAsAnyUser": true,
    "access.firstPartyCookies": false,
    "access.stabilizedHostnames": true,
    "access.logRedirections": false,
    // Password Management (NIST: expiration should be "never" = 0)
    "pwd.expirationDays": 90,
    "pwd.minLifetime": true,
    "pwd.minLength": 8,
    "pwd.history": 3,
    "pwd.complexity": "AlphaNumeric",
    "pwd.questionRestriction": "None",
    "pwd.obscureSecretAnswer": false,
    // MFA
    "mfa.allDirectUiLogins": false,
    "mfa.verifyOnRegistration": true,
    "mfa.smsIdentityVerification": true,
    "mfa.securityKeyU2F": false,
    "mfa.builtInAuthenticator": true,
    "mfa.lightningLogin": false,
    // Data Leakage
    "dlp.dashboardSnapshots": false,
    // Secure Baseline
    "baseline.pimEnhanced": false,
    "baseline.guestApiEnabled": false,
    "baseline.profileFiltering": false,
    "baseline.postForSessions": false,
    "baseline.crossOrgRedirects": true,
    "baseline.redirectBlockMode": false,
    "baseline.userSelfDeactivate": true,
    "baseline.restrictEmailDomains": false,
    // Auditing
    "audit.eventLogGeneration": true,
    "audit.eventLogDeleteDisabled": true,
    "audit.userFieldHistory": false,
  },
  permissionCounts,
  permissionAffected,
  users: [
    ...usernames(5, 20).map((u) => ({ username: u, isActive: true, lastLoginDays: 210 })), // dormant
    ...usernames(58, 40).map((u) => ({ username: u, isActive: true, lastLoginDays: 3 })),
  ],
  connectedApps: [
    {
      name: "DataLoader Pro", scopes: ["full", "refresh_token"],
      ipRelaxation: "RELAX", usesNonExpiringRefreshTokens: true,
      pkceRequired: false, clientCredentialsEnabled: true, consumerSecretOptional: true,
      introspectAllTokens: true, secretRequiredForRefresh: false,
      restrictedToProfilesOrPermSets: false, singleLogoutUrl: "",
      callbackUrl: "http://etl.internal.example.com/oauth/callback",
    },
    {
      name: "Legacy ETL Integration", scopes: ["full", "api"],
      ipRelaxation: "RELAX", usesNonExpiringRefreshTokens: true,
      pkceRequired: false, clientCredentialsEnabled: false, consumerSecretOptional: false,
      introspectAllTokens: false, secretRequiredForRefresh: false,
      restrictedToProfilesOrPermSets: false, singleLogoutUrl: "",
      callbackUrl: "https://legacy-etl.example.com/callback",
    },
    {
      name: "Marketing Cloud Connector", scopes: ["api", "refresh_token"],
      ipRelaxation: "ENFORCE", usesNonExpiringRefreshTokens: false,
      pkceRequired: true, clientCredentialsEnabled: false, consumerSecretOptional: false,
      introspectAllTokens: false, secretRequiredForRefresh: true,
      restrictedToProfilesOrPermSets: true, singleLogoutUrl: "https://mc.example.com/slo",
      callbackUrl: "https://mc.example.com/callback",
    },
    {
      name: "Tableau CRM", scopes: ["api"],
      ipRelaxation: "ENFORCE", usesNonExpiringRefreshTokens: false,
      pkceRequired: true, clientCredentialsEnabled: false, consumerSecretOptional: false,
      introspectAllTokens: false, secretRequiredForRefresh: true,
      restrictedToProfilesOrPermSets: true, singleLogoutUrl: "https://tableau.example.com/slo",
      callbackUrl: "https://tableau.example.com/callback",
    },
  ],
  externalClientApps: [
    {
      name: "PartnerPortal_ECA",
      pkceRequired: false, refreshTokenRotation: false, secretRequiredForRefresh: false,
      consumerSecretOptional: true, introspectAllTokens: true,
      callbackUrl: "http://partner.example.com/oauth/callback",
      ipRelaxation: "RELAX", clientCredentialsEnabled: true, tokenExchangeEnabled: true,
      permittedUsers: "AllSelfAuthorized", refreshTokenPolicy: "Infinite",
      refreshTokenValidityDays: null, requiredSessionLevel: "STANDARD",
    },
    {
      name: "DataSync_ECA",
      pkceRequired: true, refreshTokenRotation: false, secretRequiredForRefresh: true,
      consumerSecretOptional: false, introspectAllTokens: false,
      callbackUrl: "https://datasync.example.com/callback",
      ipRelaxation: "ENFORCE", clientCredentialsEnabled: false, tokenExchangeEnabled: false,
      permittedUsers: "AdminApprovedPreAuthorized", refreshTokenPolicy: "SpecificLifetime",
      refreshTokenValidityDays: 730, requiredSessionLevel: "STANDARD",
    },
    {
      name: "Billing_ECA",
      pkceRequired: true, refreshTokenRotation: true, secretRequiredForRefresh: true,
      consumerSecretOptional: false, introspectAllTokens: false,
      callbackUrl: "https://billing.example.com/callback",
      ipRelaxation: "ENFORCE", clientCredentialsEnabled: false, tokenExchangeEnabled: false,
      permittedUsers: "AdminApprovedPreAuthorized", refreshTokenPolicy: "SpecificInactivity",
      refreshTokenValidityDays: 90, requiredSessionLevel: "HIGH_ASSURANCE",
    },
  ],
  certificates: [
    { name: "SSO_Signing_Cert", daysToExpiry: -12, keySize: 2048, caSigned: true, privateKeyExportable: false },
    { name: "Partner_mTLS", daysToExpiry: 43, keySize: 2048, caSigned: true, privateKeyExportable: true },
    { name: "Legacy_SelfSigned", daysToExpiry: 512, keySize: 1024, caSigned: false, privateKeyExportable: false },
    { name: "Payments_Gateway", daysToExpiry: 610, keySize: 4096, caSigned: true, privateKeyExportable: false },
  ],
  publicLinksNoPassword: ["Q3 Board Deck.pptx", "2026 Pricing.xlsx", "Underwriting Playbook.pdf"],
  objectsPublicExternal: ["Account", "Contact"],
  guestSharingRules: ["Guest_Case_Read_All", "Community_Account_Share"],
};
