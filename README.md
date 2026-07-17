# OrgSentinel (working name)

An external, agentless **Security Posture Management (SSPM) scanner for Salesforce** —
a self-owned equivalent of CrowdStrike Falcon Shield's Salesforce SSPM, with a custom,
extensible rule catalog and branded compliance exports.

Connect to any org via OAuth (like Workbench) → run a rule catalog you own → score
posture → map findings to compliance frameworks → export the report → track drift.

## Status: design phase (no app built yet)

- [`DESIGN.md`](./DESIGN.md) — architecture, connection/OAuth model, rule engine, export, roadmap.
- [`CHECK_CATALOG.md`](./CHECK_CATALOG.md) — the check catalog mapped to Salesforce APIs + compliance frameworks.

Design decisions locked so far: external web app · Health Check API first · JSON/YAML
custom rules.
