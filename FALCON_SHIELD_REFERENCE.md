# Reference: CrowdStrike Falcon Shield → OrgSentinel replication map

Falcon Shield (formerly Adaptive Shield) is CrowdStrike's **SaaS Security Posture
Management (SSPM)** platform: connects to 200+ SaaS apps by API, runs **3,500+
configuration checks**, and covers eight capability pillars. Our sample report
(`PLADS_Test_Security Checks.csv`) is a Falcon Shield export for a Salesforce org.

Source: CrowdStrike Falcon Shield product pages + "Key features and capabilities" data sheet (2026).

## The 8 Falcon Shield pillars and our coverage (Salesforce-scoped)

| # | Falcon Shield pillar | What it does | OrgSentinel coverage | How (Salesforce) |
|---|---|---|---|---|
| 1 | **Misconfiguration Management** | 3,500+ config checks; severity, app score, affected users, compliance, remediation | ✅ Core | Health Check API + Metadata API + SOQL (see `CHECK_CATALOG.md`) |
| 2 | **Permissions Inventory** | Entitlements down to object/field level (Salesforce showcased) | ✅ Full | SOQL: `PermissionSet`, `PermissionSetAssignment`, `ObjectPermissions`, `FieldPermissions`, `SetupEntityAccess` |
| 3 | **Identity Security Posture** | Human + non-human identities (NHI) + AI agents; dormant, over-privileged, external, deprovisioning | ✅ Mostly | `User` (`LastLoginDate`, `IsActive`, `UserType`), community/external users, integration/API-only users as NHIs |
| 4 | **Data Inventory** | Public / externally shared files; owner, dates, expiration, password | ✅ Full | `ContentDistribution` (public links), `ContentDocumentLink` (external shares), sharing settings |
| 5 | **SaaS Threat Detection** | Behavioral: password spray, credential stuffing, impossible travel, abnormal downloads; MITRE ATT&CK | ⚠️ Partial | Batch/near-real-time from `LoginHistory` + Event Monitoring; MITRE labels. Not full cross-SaaS ML |
| 6 | **AI Agent Discovery** | Discover AI agents, configs, permissions, anomalous behavior | ✅ Full (bonus) | Agentforce agents/topics/permissions — reuses AgentLens work |
| 7 | **Shadow SaaS Discovery** | Unsanctioned SaaS via endpoint DNS telemetry | ❌ Out of scope | Requires CrowdStrike endpoint agent; not possible from a single-org connection |
| 8 | **Device-to-SaaS Posture** | Device hygiene (Falcon ZTA score) vs SaaS access | ❌ Out of scope | Requires endpoint/MDM telemetry. `LoginHistory` gives browser/OS only, no device posture score |

## Cross-cutting Falcon Shield capabilities (all replicable)
- Near-real-time **configuration-drift alerts** + **ticketing** (Slack/Jira/ServiceNow).
- **Fully configurable custom security checks** (our JSON rule engine).
- **23 built-in compliance frameworks** + custom policies (we map ISO 27001, NIST 800-53, SOC 2, CSA CCM, PCI-DSS, NIST CSF to start).
- **Centralized dashboard** with per-app / per-domain security scores.
- Each finding: severity, affected users, impacted compliance, remediation steps.

## Scoping takeaway
OrgSentinel can faithfully replicate the **Salesforce SSPM** — pillars 1–4 and 6 fully,
5 partially — which is exactly what the sample report covers. Pillars 7–8 exist only
because CrowdStrike also owns the endpoint agent, so they are intentionally out of scope
for a standalone Salesforce connected-app tool (and would be a dishonest promise).

**Differentiator vs. Falcon Shield:** self-owned + fully customizable rule catalog,
Salesforce depth (object/field-level + Agentforce agent posture), regulated-industry
compliance exports, and multi-org ProServe assessments — without the enterprise SSPM price tag.
