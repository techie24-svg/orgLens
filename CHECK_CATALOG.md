# OrgSentinel — Check Catalog (v1 draft)

Derived from the reference Falcon Shield report, mapped to how each check is fetched
through a connected app. Every row becomes a JSON rule (see `DESIGN.md` §3.2).

**Source legend**
- `HC` — native **Health Check API** (Tooling: `SecurityHealthCheck` / `SecurityHealthCheckRisks`)
- `MD` — **Metadata API** (`readMetadata`/retrieve of `SecuritySettings`, `SharingRules`, `Profile`, `RemoteSiteSetting`, `CorsWhitelistOrigin`, `SitesSettings`, `MyDomainSettings`, etc.)
- `SOQL` — REST/Tooling **query**
- `MIX` — combination

**Coverage note:** managed-package connected apps are not fully retrievable via API —
a known gap we surface explicitly (the reference tool has the same limitation).

---

## Malware Protection

| Check ID | Title | Sev | Source | Probe / field | Pass condition | Compliance (short) |
|---|---|---|---|---|---|---|
| `malware.clickjack_setup` | Clickjack Protection for Setup Pages | High | HC/MD | `SecuritySettings.clickjackProtectionLevel` | enabled (default) | ISO A.8.7/A.8.26; NIST SC-23; SOC2 CC6.8 |
| `malware.clickjack_nonsetup` | Clickjack Protection Non-Setup Pages | High | HC/MD | same, non-setup | enabled | ” |
| `malware.clickjack_vf_std` | Clickjack — Customer VF (standard headers) | High | MD | VF clickjack setting | enabled | ” |
| `malware.clickjack_vf_nohdr` | Clickjack — Customer VF (disabled headers) | High | MD | VF clickjack setting | enabled | ” |
| `malware.csrf_get` | CSRF Protection (GET, non-setup) | High | HC/MD | `enableCSRFOnGet` | enabled | ISO A.8.26; NIST AC-6(1); SOC2 CC6.8 |
| `malware.csrf_post` | CSRF Protection (POST, non-setup) | High | HC/MD | `enableCSRFOnPost` | enabled | ” |
| `malware.coep_vf` | Cross-Origin Embedder Policy (COEP) VF | High | MD | VF cross-origin headers | enabled | ISO A.8.26; SOC2 CC6.8 |
| `malware.coop_vf` | Cross-Origin Opener Policy (COOP) VF | High | MD | VF cross-origin headers | enforced | ” |
| `malware.cors_oauth` | CORS for OAuth Endpoints | High | MD | CORS policy settings | **disabled** | ” |
| `malware.content_sniffing` | Content Sniffing Protection | Med | MD | `enableContentSniffingProtection` | enabled | ISO A.8.7; NIST SI-10 |
| `malware.html_upload` | HTML Files Upload blocked | Med | MD | file-upload security | HTML blocked | NIST SI-10(5) |
| `malware.risky_filetypes` | Risky File Types Execute in Browser | Med | MD | download behavior = Download | enforced | NIST SI-3 |
| `malware.custom_site_xss` | Custom Sites XSS Protection | Med | MD | `SitesSettings` per site | enabled all sites | NIST SI-10 |
| `malware.guest_file_upload` | Prevent Guest User File Upload | Med | MD | Files general settings | disabled | ISO A.8.7 |

## Access Control

| Check ID | Title | Sev | Source | Probe / field | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `access.invalid_login_attempts` | Max Invalid Login Attempts set | High | HC/MD | password policy `lockoutInterval`/attempts | not "No Limit" | ISO A.8.5; NIST AC-7 |
| `access.remote_site_https` | Remote Sites use HTTPS | High | MD | `RemoteSiteSetting.disableProtocolSecurity` | false for all | ISO A.8.21/A.8.24; NIST SC-8(3) |
| `access.sso_enabled` | SAML SSO Enabled | High | MD | `SamlSsoConfig` exists/active | enabled | NIST IA-2(10); SOC2 CC6.1 |
| `access.enforce_custom_domain` | Enforce Auth Through My Domain | High | MD | `MyDomainSettings` login policy | prevent login.salesforce.com | ISO A.8.5; NIST IA-2(10) |
| `access.connected_app_allowlist` | Limit Connected Apps API Access | High | MD | API Access Control setting | activated | ISO A.8.26; NIST AC-6(10) |
| `access.oauth_full_scope` | OAuth Apps with Full Scope | High | SOQL | `ConnectedApplication` scopes contains `full` | none (or reviewed) | ISO A.8.3; NIST AC-6(10) |
| `access.inactive_session_logout` | Force logout on session timeout | Med | HC/MD | `forceLogoutOnTimeout` | enabled | ISO A.5.18; NIST AC-12 |
| `access.relogin_login_as` | Re-login after Login-As-User | Med | MD | `enableLoginAsUserRelogin`-equiv | enabled | NIST SC-3(2) |
| `access.ip_every_request` | Enforce login IP ranges every request | Med | HC/MD | `enforceIpRangesEveryRequest` | enabled | NIST SC-7(5) |
| `access.sms_identity_verification` | Identity Verification with SMS | Med | MD | session settings | enabled | NIST IA-2 |
| `access.warn_redirect` | Warn on Redirect Out of Salesforce | Med | MD | external redirection policy | "with user permission" | NIST AC-3(3) |
| `access.trusted_ip_ranges` | Trusted IP Ranges configured | Med | MD | `NetworkAccess` ranges | configured | ISO A.8.5; NIST SC-7(5) |
| `access.connected_app_ip` | Connected App IP Restriction | High | SOQL/MD | app `ipRelaxation` | enforce for all | NIST AC-6(10) |

## Password Management

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `pwd.expiration_org` | Password Expiration (org policy) | High | HC/MD | `passwordExpiration` | 0 (never) per NIST | NIST IA-5(1); ISO A.8.5 |
| `pwd.expiration_profile` | Profile Password Expiration | High | MD | per-`Profile` password policy | 0 for all | ” |
| `pwd.min_lifetime` | Min 1-day password lifetime | Med | HC/MD | `minimumPasswordLifetime` | enabled | NIST IA-5(1) |
| `pwd.min_length` | Minimum Password Length ≥ 8 | Med | HC/MD | `minimumPasswordLength` | ≥ 8 | NIST IA-5(1); PCI 8.3.6 |
| `pwd.history` | Password History ≥ 1 | Med | HC/MD | `passwordHistory` | ≥ 1 | NIST IA-5(1) |

## Permissions (over-permissioning — threshold-based)

All via `SOQL` on `PermissionSetAssignment` + `PermissionSet` (incl. profile-owned)
filtering the relevant `Permissions*` field; `affectedQuery` returns offending usernames.

| Check ID | Title | Sev | Permission field | Threshold |
|---|---|---|---|---|
| `perm.view_all_data` | Users with View All Data | High | `PermissionsViewAllData` | ≤ 15 |
| `perm.modify_all_data` | Users with Modify All Data | High | `PermissionsModifyAllData` | ≤ 15 |
| `perm.use_any_api_client` | Users with Use Any API Client | High | `PermissionsApiUserOnly`/UseAnyApiClient | ≤ 5 |
| `perm.manage_users` | Users with Manage Users | Med | `PermissionsManageUsers` | ≤ 17 |
| `perm.bulk_hard_delete` | Users with Bulk API Hard Delete | Med | `PermissionsBulkApiHardDelete` | ≤ 15 |
| `perm.super_combo` | Users with Super Permissions (VAD+MAD+ManageUsers) | Med | all three | ≤ 10 |
| `perm.weekly_export` | Users with Weekly Data Export | Med | `PermissionsDataExport` | ≤ 15 |
| `perm.delete_accounts` | Users who can Delete Accounts | Med | `ObjectPermissions` (Account, delete) | ≤ 5 |

_Compliance (all rows): ISO A.8.2/A.8.3/A.5.18; NIST AC-6(7); SOC2 CC6.1; PCI 7.2.4/7.2.5.1._

## MFA

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `mfa.privileged_users` | 2FA for Highly Privileged Users | High | MIX | privileged-perm holders ∩ MFA/high-assurance | all have MFA | NIST IA-2(1); PCI 8.5.1 |
| `mfa.verify_on_registration` | Identity Verification during MFA Registration | Med | MD | session setting | enabled | ISO A.8.5; NIST IA-2 |

## Data Leakage Protection

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `dlp.guest_sharing_rules` | Guest Profile Sharing Rules (Digital Experience) | High | MD | `SharingRules` w/ guest | none | ISO A.8.12; NIST AC-21 |
| `dlp.owd_public` | Objects w/ Default External Access = Public | High | MD | OWD external access | private for all | ” |
| `dlp.dashboard_snapshots` | Dashboard Component Snapshots | High | MD | analytics settings | disabled | ” |
| `dlp.public_links` | Public Links Enabled | High | MD | Files public links setting | disabled | ” |
| `dlp.content_delivery_pwd` | Content Deliveries Password Default | High | MD | content delivery defaults | password required | NIST AC-6(6) |
| `dlp.public_links_nopwd` | Public Links/Deliveries w/o Password | High | SOQL | `ContentDistribution` w/o password | none | ISO A.8.12 |
| `dlp.portal_user_visibility` | Portal User Visibility | High | MD | sharing settings | disabled | ISO A.8.12 |
| `dlp.site_user_visibility` | Site User Visibility | High | MD | sharing settings | disabled | ” |
| `dlp.custom_site_hide_url` | Custom Sites Hide Full URL | Med | MD | `SitesSettings` referrer | enabled all | NIST SC-8(2) |

## Secure Baseline

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `baseline.pim_enhanced` | Enhanced Personal Information Management | High | MD | User Management Settings | enabled | ISO A.5.34; NIST PR.AA-01 |
| `baseline.guest_api_enabled` | Guest Profile w/ API Enabled | High | MD | guest `Profile.PermissionsApiEnabled` | disabled all | NIST AC-6(10) |
| `baseline.guest_permissive` | Guest Profile Permissive Permissions | High | MD | guest `Profile` perm set (denylist) | none flagged | ISO A.8.2; IAM-05 |
| `baseline.profile_filtering` | Profile Filtering for Guest Users | High | MD | User Management Settings | enabled | ISO A.8.9/A.5.34 |
| `baseline.canvas_nonadmin` | Disable Canvas App Install by Non-Admins | Med | MD | connected app access settings | disabled | NIST CM-11(2) |

## Auditing

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `audit.event_log_generation` | Event Log Generation Enabled | High | MD | Event Monitoring settings | enabled | — |
| `audit.no_delete_event_records` | Deletion of Event Monitoring Records Disabled | High | MD | Event Monitoring settings | delete off | — |

## Privacy Control

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `privacy.view_pii` | Users with Permission to View PII | Med | SOQL | `PermissionsViewRoles`/View PII-equiv | = 0 | ISO A.5.34; NIST AC-6(7) |

## Connected Apps

Sourced from `listMetadata("ConnectedApp")` followed by `readMetadata`, reading each app's
nested `oauthConfig` and `oauthPolicy`. Every check is `listEmpty` over a derived list, so a
failure names the offending apps in the Affected column.

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `capp.oauth_full_scope` | Connected Apps With Full Access OAuth Scope | High | MD | `oauthConfig.scopes` | no app has `full` | ISO A.5.15; NIST AC-6 |
| `capp.ip_relaxation` | Connected App IP Restrictions Enforced | High | MD | `oauthPolicy.ipRelaxation` | none `RELAX` | ISO A.8.20; NIST AC-17 |
| `capp.nonexpiring_refresh` | Connected Apps With Non-Expiring Refresh Tokens | High | MD | `oauthPolicy.refreshTokenPolicy` | none `infinite` | ISO A.5.17; NIST AC-12 |
| `capp.pkce_required` | OAuth PKCE Requirement | High | MD | `oauthConfig.isPkceRequired` | all true | ISO A.8.5; NIST IA-2 |
| `capp.client_credentials` | OAuth Client Credentials Flow Restricted | High | MD | `oauthConfig.isClientCredentialEnabled` | all false | ISO A.5.16; NIST AC-6 |
| `capp.secret_required` | Consumer Secret Required | High | MD | `oauthConfig.isConsumerSecretOptional` | all false | ISO A.5.17; NIST IA-5 |
| `capp.refresh_secret` | Secret Required For Refresh Token Exchange | Med | MD | `oauthConfig.isSecretRequiredForRefreshToken` | all true | ISO A.5.17; NIST IA-5 |
| `capp.introspect_all` | Token Introspection Limited To Own Tokens | Med | MD | `oauthConfig.isIntrospectAllTokens` | all false | ISO A.5.15; NIST AC-6 |
| `capp.restricted_audience` | Connected Apps Limited To Specific Profiles Or Permission Sets | Med | MD | `profileName` / `permissionSetName` | at least one set | ISO A.5.15; NIST AC-3 |
| `capp.single_logout` | Connected App Single Logout Configured | Low | MD | `oauthPolicy.singleLogoutUrl` | present | ISO A.8.5; NIST AC-12 |
| `capp.https_callback` | Connected App Callback URLs Use HTTPS | High | MD | `oauthConfig.callbackUrl` | no plaintext `http://` | ISO A.8.24; NIST SC-8 |

## External Client Apps

The Connected App successor, and a separate metadata family — the `capp.*` rules above do
not see these apps. Credential handling is read from `ExtlClntAppGlobalOauthSettings` and
runtime policy from `ExtlClntAppOauthConfigurablePolicies`; the two are joined on their
shared `externalClientApplication` back-reference.

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `eca.pkce_required` | External Client App PKCE Requirement | High | MD | `isPkceRequired` | all true | ISO A.8.5; NIST IA-2 |
| `eca.refresh_rotation` | External Client App Refresh Token Rotation | Med | MD | `isRefreshTokenRotationEnabled` | all true | ISO A.5.17; NIST IA-5 |
| `eca.refresh_secret` | External Client App Secret Required For Refresh Token | Med | MD | `isSecretRequiredForRefreshToken` | all true | ISO A.5.17; NIST IA-5 |
| `eca.consumer_secret_required` | External Client App Consumer Secret Required | High | MD | `isConsumerSecretOptional` | all false | ISO A.5.17; NIST IA-5 |
| `eca.introspect_all` | External Client App Token Introspection Limited | Med | MD | `isIntrospectAllTokens` | all false | ISO A.5.15; NIST AC-6 |
| `eca.https_callback` | External Client App Callback URLs Use HTTPS | High | MD | `callbackUrl` | no plaintext `http://` | ISO A.8.24; NIST SC-8 |
| `eca.ip_relaxation` | External Client App IP Restrictions Enforced | High | MD | `ipRelaxationPolicyType` | none `Relax` | ISO A.8.20; NIST AC-17 |
| `eca.client_credentials` | External Client App Client Credentials Flow Restricted | High | MD | `isClientCredentialsFlowEnabled` | all false | ISO A.5.16; NIST AC-6 |
| `eca.token_exchange` | External Client App Token Exchange Flow Restricted | Med | MD | `isTokenExchangeFlowEnabled` | all false | ISO A.5.15; NIST AC-6 |
| `eca.permitted_users` | External Client App Permitted Users Are Admin-Approved | Med | MD | `permittedUsersPolicyType` | none `AllSelfAuthorized` | ISO A.5.15; NIST AC-3 |
| `eca.refresh_policy` | External Client Apps Without Non-Expiring Refresh Tokens | High | MD | `refreshTokenPolicyType` | none `Infinite` | ISO A.5.17; NIST AC-12 |
| `eca.refresh_validity` | External Client App Refresh Token Validity Within One Year | Low | MD | `refreshTokenValidityPeriod` + `Unit` | <= 365 days | ISO A.5.17; NIST AC-12 |
| `eca.session_level` | External Client App Requires High Assurance Session | Low | MD | `requiredSessionLevel` | all `HIGH_ASSURANCE` | ISO A.8.5; NIST IA-2(1) |

## Key Management

Sourced from `listMetadata("Certificate")` followed by `readMetadata`. Expiry is evaluated as
days relative to scan time, so results shift as certificates age.

| Check ID | Title | Sev | Source | Probe | Pass condition | Compliance |
|---|---|---|---|---|---|---|
| `key.no_expired_certs` | No Expired Certificates | High | MD | `expirationDate` | none in the past | ISO A.8.24; NIST SC-12 |
| `key.certs_expiring_soon` | No Certificates Expiring Within 90 Days | Med | MD | `expirationDate` | none within 90 days | ISO A.8.24; NIST SC-12 |
| `key.min_key_size` | Certificate Key Length At Least 2048 Bits | High | MD | `keySize` | none < 2048 | ISO A.8.24; NIST SC-13; PCI 4.2.1 |
| `key.ca_signed` | Certificates Are CA-Signed | Med | MD | `caSigned` | all true | ISO A.8.24; NIST SC-12 |
| `key.private_key_not_exportable` | Certificate Private Keys Not Exportable | High | MD | `privateKeyExportable` | all false | ISO A.8.24; NIST SC-12 |

---

## Notes for implementation
- Store `Affected` and `Ratio` as **text** (avoid Excel date coercion of `7/16`, `1/63`).
- Health Check API gives a built-in risk score for the baseline settings — reuse it for
  the posture score, then extend with the SOQL/metadata checks it doesn't cover.
- Threshold defaults above match the reference report; all are per-rule editable so a
  client can tighten/loosen them.
- Each rule carries its compliance tags so the export can pivot findings by framework.
