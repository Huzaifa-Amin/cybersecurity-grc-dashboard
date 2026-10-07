# Architecture overview

Northstar is a single-organization GRC workspace built to serve a small team. The app separates the Streamlit interface, security/role checks, GRC calculations, persistence, and versioned database schema.

## Runtime request flow

```text
Browser
  -> Streamlit UI (app.py)
  -> session/account check (security.py + users table)
  -> permission-gated form and input validation (store.py)
  -> SQLAlchemy transaction
  -> PostgreSQL (shared Compose deployment) or SQLite (local use/tests)
  -> audit event for write operations
```

The app checks the current account status and authorization version on each rerun. A disabled user or a session invalidated by an account/password update is redirected to sign-in. Viewers can read/export; editors can create/update controls; administrators can additionally delete controls, manage users, and view audit events.

## Components

| File or service | Responsibility |
|---|---|
| `app.py` | Sign-in and first-admin flow, dashboards, sidebar filters, register and evidence views, account and audit UI. |
| `src/grc_dashboard/exporting.py` | Register DataFrame and CSV creation with spreadsheet-formula neutralization for untrusted text. |
| `src/grc_dashboard/security.py` | Username/password rules, salted PBKDF2-HMAC-SHA-256, password verification, and role permission predicates. |
| `src/grc_dashboard/store.py` | SQLAlchemy table metadata, migration startup, one-time sample seed, input validation, account/control persistence, password lifecycle, and audit writes. |
| `src/grc_dashboard/risk_engine.py` | Control maturity averages, framework counts, risk distribution, and priority ordering. |
| `migrations/` | Alembic version history applied at application startup. |
| `database` Compose service | PostgreSQL 16 and a persistent named data volume. The database port is not published to the host. |

## Database entities

- **users:** username, display name, password hash, role, enabled flag, temporary-password requirement, authentication version, and creation time.
- **controls:** control ID and name, domain/framework, owner, implementation state, maturity score, risk rating, due date, evidence reference, notes, and timestamps.
- **audit_log:** actor, action, entity, event details, and timestamp for successful account/control mutations.
- **app_settings:** one-time starter-data seed marker, preventing an intentionally cleared control table from repopulating after restart.
- **alembic_version:** schema migration revision.

The app stores evidence references only. It does not accept or serve evidence files.

## Data initialization and migrations

On startup, Alembic applies pending schema revisions. The application then seeds illustrative control records once, when the register is empty and no seed marker exists. It never creates a shared default password. The first administrator is created by an onboarding flow requiring an operator-configured token of at least 32 characters. Later accounts are provisioned by an administrator.

Back up the database before deployments that may apply migrations. Check the schema revision, application logs, and backups as part of the release procedure.

## Risk calculations

- Overall control maturity is the arithmetic mean of `status_score` for the current filtered set, rounded to one decimal place.
- Priority is `(risk severity index * 25) + (100 - status_score)`, with Low=0, Moderate=1, High=2, Critical=3; higher values appear first.
- Overdue actions are controls past their due date whose status is not Implemented.

These values are decision-support heuristics, not a validated likelihood-impact model or compliance determination.

## Deployment boundaries

Docker Compose runs a single Streamlit service connected to PostgreSQL and binds the host dashboard port to loopback. For remote use, put it behind a TLS reverse proxy and restrict network access. Local `streamlit run app.py` binds to loopback through `.streamlit/config.toml`; the Docker command explicitly binds inside the container so Compose can route traffic.

The design target is fewer than 1,000 registered users, not a measured throughput or availability promise. There is no high availability, SSO/MFA, multi-tenant isolation, shared login throttling, immutable external audit sink, or evidence-file service. See the [project report](PROJECT_REPORT.html), [threat model](THREAT_MODEL.md), and [runbook](RUNBOOK.md).
