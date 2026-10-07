# Northstar architecture

Northstar is a multi-organization governance, risk, and compliance (GRC) application for small teams. A single deployment can host several isolated organization workspaces. Each workspace has its own control register, memberships, groups, audit events, control history, and vulnerability triage. The application uses Streamlit for the web interface, SQLAlchemy for persistence, and Alembic for database migrations.

## Request and authorization flow

```text
Browser
  -> Streamlit UI (app.py)
  -> signed-in account and active workspace selection
  -> service-layer membership and minimum-role check (store.py)
  -> workspace-scoped SQLAlchemy query or transaction
  -> PostgreSQL (shared deployment) or SQLite (local use/tests)
  -> same-transaction audit event for supported writes
```

Navigation and hidden buttons are not the security boundary. Every data service validates the active account, its membership in the requested organization, and the required effective role before performing an operation. The effective role is the higher of the user's direct workspace role and any workspace group roles. Groups may grant `viewer` or `editor`; administrator privileges can only be assigned directly by an organization administrator.

All controls, audit events, history records, and triage records are filtered by organization in the service layer. Control IDs are unique within an organization, rather than globally. Usernames are global account identifiers; one account may hold different roles in different organizations. A workspace switch is restricted to the account's active memberships.

## Roles

| Effective role | Read / export | Create / update controls | Update threat triage | Delete controls | Manage workspace access |
|---|---:|---:|---:|---:|---:|
| Viewer | Yes | No | No | No | No |
| Editor | Yes | Yes | Yes | No | No |
| Administrator | Yes | Yes | Yes | Yes | Yes |

Each organization must retain at least one active, directly assigned administrator. Group membership cannot satisfy that requirement. Disabling or demoting a user's direct organization administrator role increments the account authorization version, invalidating existing sessions on their next app request.

## Components

| Component | Responsibility |
|---|---|
| `app.py` | Sign-in, initial administrator setup, organization switcher, overview charts, control and action pages, CISA threat-intelligence UI, and workspace/group administration. |
| `src/grc_dashboard/security.py` | Password rules and hashing, authentication checks, and reusable role predicates. |
| `src/grc_dashboard/store.py` | SQLAlchemy schema, organization-scoped services, input validation, migration startup, account lifecycle, audit events, and control history. |
| `src/grc_dashboard/risk_engine.py` | Maturity/risk summaries, 1–25 inherent-risk scoring, control ranking, and deterministic human-reviewed next-step suggestions. |
| `src/grc_dashboard/intelligence.py` | Bounded HTTPS retrieval and input validation for official CISA KEV and cybersecurity-advisory feeds. |
| `src/grc_dashboard/exporting.py` | Workspace-filtered register exports and spreadsheet formula neutralization. |
| `migrations/` | Versioned schema changes and legacy-data backfill. |
| PostgreSQL / SQLite | PostgreSQL is the intended shared deployment database; SQLite is for local development and automated tests. |

## Database entities

| Table | Workspace scope | Purpose |
|---|---|---|
| `users` | Global account | Username, display name, password hash, enabled state, password-change requirement, and authorization version. |
| `organizations` | — | Workspace names and unique slugs. |
| `organization_memberships` | Organization + user | Direct viewer/editor/administrator role and membership status. |
| `groups` | Organization | Named viewer/editor permission groups. |
| `group_memberships` | Organization + group + user | Ensures group members belong to the same active workspace. |
| `controls` | Organization + control ID | Maturity, inherent likelihood/impact, residual rating, owner, status, due date, evidence reference, and notes. |
| `control_history` | Organization + control | Timestamped status, maturity, risk, and actor snapshots on create/edit. |
| `audit_log` | Organization | Actor, action, entity, details, and timestamp for supported mutations. |
| `threat_triage` | Organization + CVE | Organization-specific analyst status and notes, separate from public CISA catalog data. |
| `app_settings` | Database | One-time, per-workspace starter-data initialization markers. |
| `alembic_version` | Database | Current database migration revision. |

Evidence is represented by a user-entered reference only; the app does not upload, scan, or serve files. Public CISA feed responses are fetched and cached in application memory; the public catalog itself is not organization-specific.

## Risk and threat-intelligence semantics

- Maturity is the arithmetic mean of the selected controls' user-entered `status_score` values, rounded to one decimal place.
- Inherent risk is an analyst estimate: `likelihood (1–5) × impact (1–5)`. Bands are Low (1–4), Moderate (5–9), High (10–16), and Critical (17–25).
- The separate residual risk rating is also entered by the control owner/editor. The app does not infer it from public feeds.
- Priority is `(residual risk index × 25) + (100 − maturity)`, where Low=0, Moderate=1, High=2, and Critical=3. This is a transparent sorting heuristic, not a probability or calibrated forecast.
- Domain-specific next-step text is deterministic guidance for human review, not an automated remediation plan.
- CISA Known Exploited Vulnerabilities (KEV) and CISA advisory feeds are official public sources, fetched on demand and cached for up to one hour. Their retrieval timestamp and source links are shown.
- A KEV listing is not evidence that an organization's system is affected. Northstar has no asset/software inventory or automatic exposure matching. An authorized analyst records workspace triage after checking the organization's own environment.

## Initialization and deployment boundaries

Alembic upgrades the configured database at app startup. Existing data is preserved by the migration backfill; illustrative controls are seeded once per workspace. The first administrator is claimed using a high-entropy operator-configured bootstrap token. No default account is provisioned.

Docker Compose provides a single Streamlit instance and PostgreSQL with persistent storage. The host app port is loopback-bound by default. Remote access requires a separately configured HTTPS reverse proxy and network restrictions. This design targets fewer than 1,000 registered users, but that number is not a measured throughput, concurrency, uptime, or capacity guarantee.

Known exclusions include SSO/MFA, e-mail invitations and self-service recovery, shared/distributed login rate limiting, evidence-file storage, an external immutable audit sink, high availability, and production load testing. See the [project report](PROJECT_REPORT.html), [setup guide](SETUP.md), [runbook](RUNBOOK.md), and [threat model](THREAT_MODEL.md).
