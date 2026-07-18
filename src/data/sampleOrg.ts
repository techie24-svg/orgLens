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
    "access.connectedAppAllowlist": false,
    "access.forceLogoutOnTimeout": true,
    "access.ipEveryRequest": true,
    "access.warnRedirect": false,
    "access.requireMyDomainForApi": false,
    // Password Management (NIST: expiration should be "never" = 0)
    "pwd.expirationDays": 90,
    "pwd.minLifetime": true,
    "pwd.minLength": 8,
    "pwd.history": 3,
    // MFA
    "mfa.allDirectUiLogins": false,
    "mfa.verifyOnRegistration": true,
    // Data Leakage
    "dlp.dashboardSnapshots": false,
    "dlp.publicLinksEnabled": true,
    "dlp.contentDeliveryPasswordDefault": true,
    // Secure Baseline
    "baseline.pimEnhanced": false,
    "baseline.guestApiEnabled": false,
    "baseline.profileFiltering": false,
    "baseline.canvasNonAdminInstall": false,
    // Auditing
    "audit.eventLogGeneration": true,
    "audit.eventLogDeleteDisabled": true,
    // Privacy
    "privacy.scramblePersonalData": false,
  },
  permissionCounts,
  permissionAffected,
  users: [
    ...usernames(5, 20).map((u) => ({ username: u, isActive: true, lastLoginDays: 210 })), // dormant
    ...usernames(58, 40).map((u) => ({ username: u, isActive: true, lastLoginDays: 3 })),
  ],
  connectedApps: [
    { name: "DataLoader Pro", scopes: ["full", "refresh_token"], ipRelaxation: "RELAX", usesNonExpiringRefreshTokens: true },
    { name: "Legacy ETL Integration", scopes: ["full", "api"], ipRelaxation: "RELAX", usesNonExpiringRefreshTokens: true },
    { name: "Marketing Cloud Connector", scopes: ["api", "refresh_token"], ipRelaxation: "ENFORCE", usesNonExpiringRefreshTokens: false },
    { name: "Tableau CRM", scopes: ["api"], ipRelaxation: "ENFORCE", usesNonExpiringRefreshTokens: false },
  ],
  publicLinksNoPassword: ["Q3 Board Deck.pptx", "2026 Pricing.xlsx", "Underwriting Playbook.pdf"],
  objectsPublicExternal: ["Account", "Contact"],
  guestSharingRules: ["Guest_Case_Read_All", "Community_Account_Share"],
};
