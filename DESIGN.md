# OrgSentinel — Salesforce Security Posture Management (SSPM)

> Working name. An external, agentless security-posture scanner for Salesforce orgs —
> a self-owned equivalent of CrowdStrike Falcon Shield's Salesforce SSPM, with a
> custom, extensible rule catalog and branded compliance exports.

## 1. Problem & positioning

Salesforce orgs drift into insecure states — over-permissioned users, permissive
guest/community profiles, weak session/password policies, public OWD, full-scope
connected apps. Existing tooling:

- **Salesforce Health Check** (native, free) — baseline *settings* only, single org,
  no user/permission analysis, no export, no custom rules.
- **Salesforce Security Center** (paid add-on) — multi-org, but licensed and not
  customizable at the rule level.
- **CrowdStrike Falcon Shield / other SSPM vendors** — strong, but a paid catalog you
  don't control.

**OrgSentinel's wedge:** connect to *any* org via OAuth (like Workbench), run a rule
catalog **you own and extend**, map findings to the compliance frameworks regulated
clients require, and export a branded report. Ideal for **ProServe / REG security
assessments run across many client orgs**.

Analogy to CrowdStrike CSPM/SSPM: agentless API connection → continuous scan for
misconfig + over-permissioning + compliance violations → prioritized findings →
guided remediation → drift tracking over time. OrgSentinel is that loop, scoped to
Salesforce.

## 2. Goals / non-goals

**Goals**
- Agentless connection to any org via OAuth 2.0 (interactive) or JWT (unattended).
- Declarative, user-extensible rule catalog (JSON/YAML), no redeploy to add a rule.
- Full parity with the reference Falcon Shield report schema + compliance mappings.
- Drift detection across scans (status-change dates).
- Branded CSV / XLSX / PDF export.
- Multi-org support for assessment engagements.

**Non-goals (v1)**
- Real-time threat detection / SIEM (this is *posture*, not runtime IOAs).
- Auto-remediation that writes to the org (v1 is read-only + guided remediation;
  automated fixes are a later, opt-in phase).

## 3. Architecture

```
┌─────────────┐     OAuth / JWT     ┌───────────────────────────┐
│  Browser UI │◄───────────────────►│  OrgSentinel backend (Node)│
│ (React/Vite)│                     │                            │
└─────────────┘                     │  ┌──────────────────────┐  │
       ▲                            │  │ Connection manager   │  │  ── Salesforce org(s)
       │ findings / reports         │  │ (token store, multi- │──┼──►  REST / Tooling /
       │                            │  │  org)                │  │     Metadata / SOQL
       │                            │  ├──────────────────────┤  │
       │                            │  │ Rule engine          │  │
       │                            │  │  - loads JSON rules  │  │
       │                            │  │  - source adapters:  │  │
       │                            │  │    healthcheck/soql/ │  │
       │                            │  │    metadata/apex     │  │
       │                            │  │  - evaluator         │  │
       │                            │  ├──────────────────────┤  │
       │                            │  │ Scan runner + differ │  │
       │                            │  │ (drift vs last run)  │  │
       │                            │  ├──────────────────────┤  │
       │                            │  │ Report/export        │  │
       │                            │  │ (CSV/XLSX/PDF)       │  │
       │                            │  └──────────────────────┘  │
       │                            └───────────────────────────┘
```

### 3.1 Connection layer
- **Interactive:** OAuth 2.0 web-server flow (like Workbench) — user authorizes,
  we store a refresh token. Login-host selectable (prod / sandbox / My Domain).
- **Unattended / scheduled:** JWT bearer flow with a dedicated **integration user**
  (least-privilege, read-only permission set — see the reference permissions list).
- **Scopes:** `api`, `refresh_token`, `web`. No write scopes in v1.
- **Token storage:** encrypted at rest; per-org connection records.

### 3.2 Rule engine (the core)
Every check — built-in or custom — is a declarative rule. Rules are loaded from a
catalog directory (`rules/*.json`) plus any user-supplied files, so **adding a rule
never requires a code change**.

```jsonc
{
  "id": "perm.view_all_data",
  "domain": "Permissions",
  "severity": "High",
  "title": "Users with Permission to View All Data",
  "description": "The View All Data permission bypasses all sharing...",
  "source": {
    "type": "soql",                       // healthcheck | soql | metadata | apex
    "query": "SELECT COUNT() FROM PermissionSetAssignment WHERE PermissionSet.PermissionsViewAllData = true AND Assignee.IsActive = true"
  },
  "evaluate": { "metric": "count", "op": "<=", "threshold": 15 },
  "affectedQuery": "SELECT Assignee.Username FROM PermissionSetAssignment WHERE PermissionSet.PermissionsViewAllData = true",
  "remediation": "Review users with View All Data and remove where not business-critical.",
  "compliance": {
    "NIST_800_53": ["AC-6(7)"],
    "SOC2": ["CC6.1"],
    "ISO_27001_2022": ["A.8.2", "A.8.3"],
    "PCI_DSS_4": ["7.2.4", "7.2.5.1"]
  },
  "enabled": true,
  "tags": ["over-permissioning"]
}
```

**Source adapters:**
| type | how it fetches | covers |
|---|---|---|
| `healthcheck` | Tooling API `SecurityHealthCheck` / `SecurityHealthCheckRisks` | baseline session/password/session settings with risk scores |
| `soql` | REST/Tooling query | permission & user counts, connected apps, OAuth tokens |
| `metadata` | Metadata API `readMetadata` / retrieve | SecuritySettings, SharingRules, Profiles, RemoteSiteSettings, CORS, Sites |
| `apex` (later) | anonymous Apex / packaged invocable | checks not exposable via API |

**Evaluator** compares the fetched `metric` (count / boolean / value) against an
`op` + `threshold`, producing `Passed` / `Failed` and the `Affected` + `Ratio`
values (stored as **text** to avoid the Excel `7/16 → 16-Jul` corruption seen in the
reference CSV).

Thresholds, severity, and compliance tags are all editable per rule; a rule pack can
be scoped to a client or a framework.

### 3.3 Scan runner + drift
- Runs all enabled rules for a connection, in parallel with rate-limiting.
- Persists each run; **diffs against the previous run** to set `Status change date`
  (new failures, newly-passed, changed ratios) — the "continuous monitoring" behavior.
- Records `Creation Time`, `Last Run` per check.

### 3.4 Report / export
Output columns mirror the reference report exactly:
`Status, Integration, Alias, Security domain, Impact, Affected, Ratio, Security check,
Description, Info, Remediation, Status change date, Business Owner, Org domain, ticket,
Creation Time, Last Run, Tags, Check ID, ISO 27001, NIST 800-53, SOC 2, CSA CCM,
PCI-DSS 4.0, NIST CSF 2.0, Salesforce Guest-User Best Practices, SaaS NHI Benchmark`.
Formats: CSV, XLSX (styled), PDF (branded).

### 3.5 UI
- **Dashboard:** posture score, pass/fail by domain, severity breakdown, trend over time.
- **Findings:** filterable table (domain, severity, status), detail drawer with
  Info + Remediation + compliance mappings + affected entities.
- **Rules:** view/enable/disable/edit rules; import custom rule packs; per-org scoping.
- **Connections:** manage orgs, run scan, schedule.

### 3.6 AI layer (differentiator)
- Auto-draft remediation steps + severity rationale for **custom** checks.
- "What changed since last scan" plain-English summary.
- Suggest compliance-framework mappings for new custom rules.

## 4. Security considerations
- Read-only scopes; least-privilege integration user (per reference permission set).
- Encrypt stored refresh tokens; per-org isolation; audit log of scans.
- Never persist customer record data — only aggregate counts + offending identifiers
  needed for remediation.
- Honor API limits (managed-package connected apps aren't fully retrievable — surfaced
  as a known coverage gap, matching the reference tool's own caveat).

## 5. Phased roadmap
1. **P1 — Baseline:** OAuth connect + wrap Health Check API → dashboard + CSV export.
2. **P2 — Advanced checks:** SOQL/metadata permission, guest-exposure, connected-app rules.
3. **P3 — Custom rules + compliance mapping + XLSX/PDF export.**
4. **P4 — Drift tracking + scheduling + multi-org.**
5. **P5 — AI remediation + (opt-in) automated fixes.**

## 6. Open questions
- Backend language/host (Node + a small server for OAuth token exchange is required —
  can't do OAuth purely client-side).
- Where tokens are stored (local desktop app vs hosted service) — affects trust model.
- Which compliance frameworks are must-have for v1 exports.
- Do we need write-back remediation, or is guided (read-only) enough for assessments.
