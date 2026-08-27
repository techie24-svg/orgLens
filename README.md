# OrgLens — Salesforce Security Posture Scanner

A self-owned, agentless **SaaS Security Posture Management (SSPM)** tool for Salesforce —
a customizable equivalent of CrowdStrike Falcon Shield's Salesforce module. OrgLens
connects to any org via OAuth (like Workbench), runs a declarative catalog of security
checks against the org's live configuration, scores posture, maps every finding to six
compliance frameworks, and exports a Falcon-Shield-parity report.

## Highlights

- **108 built-in checks** across 13 domains (Access Control, Connected Apps, External
  Client Apps, Profile Policies, Permissions, Data Leakage, Malware Protection,
  Password Management, Key Management, MFA, Secure Baseline, Auditing, Privacy),
  seeded from a real Falcon Shield report.
- **Declarative rule engine** — three check kinds (`setting`, `count`, `listEmpty`).
  Add your own checks as JSON in the UI; they're evaluated live, no code change.
- **Six compliance frameworks** — ISO 27001:2022, NIST 800-53 Rev.5, SOC 2 Type 2,
  CSA CCM, PCI-DSS 4.0, NIST CSF 2.0 — with per-control failing-clause rollups.
- **Drift detection** — flags checks whose status changed since the last scan.
- **27-column CSV export** matching the reference report schema exactly (drop-in).
- **Read-only by construction** — a scan runs as the user who authorizes it and issues
  only queries and metadata reads: no DML, no deploy, no metadata write. Authorize as an
  administrator for full coverage; anything the user can't read reports **Not Evaluated**
  rather than a false pass.

## Architecture

```
React + TS UI  ──►  Rule engine  ──►  data source
 (dashboard,        (evaluate         ├─ MockProvider  (bundled sample org, demo)
  findings,          catalog vs       └─ /api/*  serverless backend (live)
  compliance,        snapshot)             OAuth token exchange + Health Check /
  rule editor)                             Tooling / SOQL — tokens stay server-side
```

Like Workbench, OrgLens is a **hosted web app**: you OAuth into any org and all
token exchange + Salesforce API calls happen server-side (a Connected App secret and
the access token must never reach the browser). On Vercel these run as serverless
functions; locally they run under `vercel dev`, so localhost and production behave
identically.

- `src/rules/catalog.ts` — the built-in declarative check catalog.
- `src/lib/engine.ts` — evaluator (setting / count / listEmpty) + drift diff; honors
  `unavailable` data so checks a live scan can't retrieve show **Not Evaluated** (never a false pass).
- `src/lib/api.ts` — frontend client for the backend (`session`, `scan`, OAuth start, logout).
- `src/lib/report.ts` — 27-column Falcon-Shield-parity CSV exporter.
- `api/oauth/{start,callback}.ts` — OAuth 2.0 web-server flow **with PKCE**.
- `api/{session,scan,logout}.ts` — session status, live scan, disconnect.
- `api/_lib/` — encrypted-cookie session, OAuth helpers, Salesforce snapshot assembler.
- `salesforce/` — deployable read-only scanner permission set metadata.

The demo runs against a bundled sample org (`src/data/sampleOrg.ts`) that mirrors the
shape returned by a live connection, so the full scan → findings → export flow works
offline without any Salesforce credentials.

## Run

```bash
npm install

# Demo only (sample org, no backend):
npm run dev            # http://localhost:5174 → "Try demo (sample org)"

# Full app incl. live OAuth (recommended — mirrors production):
npm i -g vercel
cp .env.example .env   # fill in SF_CLIENT_ID / SF_CLIENT_SECRET / SESSION_SECRET
vercel dev             # http://localhost:3000

npm run build          # type-check + production build
```

## Connect a real org (OAuth, like Workbench)

1. In Salesforce: **Setup → App Manager → New Connected App**. Enable OAuth, set the
   callback URL to `http://localhost:3000/api/oauth/callback` (local) and
   `https://<your-app>.vercel.app/api/oauth/callback` (prod), request scopes
   `api refresh_token web`, and enable **Require PKCE**.
2. Put the app's Consumer Key/Secret and a random `SESSION_SECRET` in `.env` (see `.env.example`).
3. Assign the read-only `OrgLens Scanner` permission set (below) to the connecting user.
4. **Connections → Connect real org via OAuth** → authorize → live scan runs automatically.

## Deploy to Vercel

```bash
vercel            # link + deploy (Vite auto-detected; api/ becomes functions)
```

Then in the Vercel project: add env vars `SF_CLIENT_ID`, `SF_CLIENT_SECRET`,
`SESSION_SECRET`, and add the production callback URL to the Connected App. No
`vercel.json` is required.

## Deploy the scanner permission set

```bash
sf project deploy start -d salesforce -o <yourOrg>
```

Assign `OrgLens Scanner (Read-Only)` to the integration user the tool connects as.

## Docs

- `DESIGN.md` — full architecture and rule-engine spec.
- `CHECK_CATALOG.md` — catalog of checks mapped to Salesforce APIs and frameworks.
- `FALCON_SHIELD_REFERENCE.md` — Falcon Shield capability map and scoping decisions.
- `SUBMISSION.md` — challenge submission writeup.
