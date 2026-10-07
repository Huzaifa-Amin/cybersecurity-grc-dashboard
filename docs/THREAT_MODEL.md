# Threat model

## System and scope

Northstar is a single application deployment that can host multiple organization workspaces. It stores GRC control and risk records, named user accounts, group memberships, audit/history records, and organization-specific triage for public vulnerability identifiers. PostgreSQL is intended for shared deployment; SQLite supports local use and automated tests.

The application is not a compliance certification service, a security monitoring/response platform, an asset inventory, or an evidence document repository. Public CISA feeds are reference data: a listing does not establish that any organization is exposed.

## Assets

- Organization-scoped controls, ownership, maturity, residual risk, due dates, notes, evidence references, and vulnerability triage
- Global user credentials/hashes and per-organization direct/group permissions
- Organization-scoped audit and control history
- Database credentials, bootstrap token, database files, and backups
- Public threat-feed responses, their source links, version/date metadata, and retrieval timestamps

## Trust boundaries and actors

- **Unauthenticated browser:** can sign in or claim initial administration only before an account exists and only with the operator-configured bootstrap token.
- **Authenticated viewer:** can read and export data for active organization memberships.
- **Authenticated editor:** adds control records, updates them, and records vulnerability triage for workspaces where editor access is effective.
- **Authenticated organization administrator:** provisions members, groups, and workspaces; deletes controls; manages audit visibility. Administrator privileges are directly assigned, never granted by groups.
- **CISA public HTTPS endpoints:** provide upstream public catalog and advisory data; the app validates response size and basic structure and preserves provenance.
- **Application process:** is responsible for session checks, service-layer authorization, organization scoping, validation, and database transactions.
- **Database and backups:** hold all workspaces' durable data and must be protected independently of app roles.
- **Reverse proxy / network:** must provide TLS and restrict remote access; Compose's host port is loopback-bound by default.

## Tenant-isolation invariants

1. Every read/write affecting controls, audit events, history, or triage specifies an organization ID and checks the actor's active membership and effective role.
2. A user can select only organizations for which their own active membership is verified.
3. Group creation and membership management are organization-admin-only. Group roles are limited to viewer/editor and group members must be active members of that same organization.
4. Usernames identify global accounts; direct membership roles and group roles are workspace-specific.
5. Control IDs may be reused in different organizations; composite database keys and organization-scoped queries prevent cross-workspace collisions.
6. A workspace must retain an active direct administrator; group access cannot substitute for an administrator.
7. Tests cover cross-workspace control and triage isolation, repeated control IDs, group permission boundaries, and migration backfill.

## Threats and treatment

| Threat | Current treatment | Residual risk |
|---|---|---|
| Unauthorized first administrator | First account requires a high-entropy configured token; no default credentials. | Operators must protect the token and restrict exposure during initial setup. |
| Cross-organization disclosure or modification | Data services scope queries and mutations by organization and enforce membership/role; migration and service tests cover isolation. | Requires ongoing review of each new data path; a database administrator can bypass application checks. |
| Group grants excessive privilege | Groups can grant viewer/editor only; administrator is direct membership only; group administration requires direct/effective workspace admin. | Administrators can still assign direct administrator membership and must review access. |
| Account compromise or stolen database | Salted PBKDF2-HMAC-SHA-256 hashes, password policy, account status and authorization-version checks, forced change of temporary passwords. | No MFA, identity federation, self-service recovery, or distributed login throttling. |
| Invalid or forged record writes | Service-layer role checks, field validation, SQLAlchemy bound parameters, and database constraints. | Keep dependencies current and apply TLS/network controls in deployed environments. |
| Incorrectly inferred vulnerability exposure | Official source links and retrieval timestamps; triage is separate and workspace-scoped; no automatic asset match or exposure claim. | Analysts must validate affected product/version against their own inventory and vendor guidance. |
| Stale/unavailable upstream intelligence | HTTPS, request timeout, bounded response size, structural validation, one-hour cache, and visible feed errors. | Feed availability and source publication cadence are external; one-hour caching is not real-time monitoring. |
| Denial of service / brute force | Password hashing cost, bounded inputs and feed payloads, connection timeout, and service health checks. | No WAF, distributed throttling, high availability, or load test. |
| Evidence or sensitive notes exposed | No file upload/serving; role- and organization-scoped references. | References and notes can disclose internal metadata; minimize sensitive content and protect backups. |
| Audit tampering or repudiation | Successful supported changes record actor/action/entity/time in a database transaction. | The DB administrator can edit audit records; no external immutable sink or cryptographic chain. |
| Database loss or migration failure | Versioned Alembic migrations, data backfill tests, persistent PostgreSQL volume, documented logical backups. | A volume is not a backup; restore and PostgreSQL migration behavior need testing at deployment. |
| Misleading risk/compliance result | Documented human-entered likelihood/impact, separate residual risk, transparent sorting heuristic, and disclaimers. | Owners must validate assumptions, evidence, mappings, applicability, and treatment decisions. |

## Required deployment controls

1. Use TLS and a restricted authenticated reverse proxy for non-local access.
2. Use unique high-entropy database and bootstrap secrets; keep them out of source control and rotate them under an approved process.
3. Limit database network access and encrypt/protect backups with access controls comparable to production data.
4. Review organization admins, direct roles, groups, and members periodically; remove stale access promptly.
5. Back up before migrations and test restore procedures on a separate database.
6. Monitor app/database health and logs. Treat feed errors as unavailable external data, not as a clean bill of health.
7. Keep evidence files and secrets in approved systems. Store only safe references in Northstar.
8. Review CISA findings against the organization's inventory and authoritative vendor advisories before taking action.

## Known gaps

No SSO/MFA, e-mail invitations, self-service recovery, distributed login throttling, external append-only audit service, evidence-file storage, asset inventory/exposure matching, high availability, independent penetration test, or production load test is included. Fewer than 1,000 registered users is a design target only, not a performance guarantee.
