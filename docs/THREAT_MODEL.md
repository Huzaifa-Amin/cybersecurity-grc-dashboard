# Threat model

## System and scope

Northstar supports one organization using a shared GRC control register. The Compose target is one Streamlit app instance connected to PostgreSQL; local development and automated tests may use SQLite. Users access the app through a browser. Application-managed sessions and role checks protect dashboard actions.

Out of scope: endpoint protection, SIEM/SOC monitoring, identity-provider services, legal interpretation, evidence document storage, multi-tenant separation, and formal compliance certification.

## Assets

- Control descriptions, owners, maturity scores, risks, remediation dates, and notes
- Usernames, account roles, password hashes, and account status
- Audit events and database credentials
- Bootstrap token and database backup files
- Evidence references, which may themselves reveal internal system/document naming

## Trust boundaries and actors

- **Unauthenticated browser:** may reach first-admin setup only while no user accounts exist; setup requires the operator's bootstrap token.
- **Authenticated viewer:** may read and export the filtered register.
- **Authenticated editor:** may create and update controls.
- **Authenticated administrator:** may delete controls, manage accounts, and read the audit view.
- **New or reset account:** must replace its temporary password before accessing the dashboard.
- **Application container:** validates inputs, enforces roles, and connects to the configured database.
- **Database and backup storage:** hold durable records and require access controls independent from the app login.
- **Reverse proxy / network:** must provide TLS and restrict remote reachability; Compose's host port is loopback-bound by default.

## Threats and treatment

| Threat | Current treatment | Residual risk |
|---|---|---|
| First user claims administrator access | First account requires a separately configured bootstrap token; no default account/password exists. | Operator must protect the token and restrict reachability during setup. |
| User receives excessive permissions | Viewer, editor, and administrator capability boundaries; account deactivation and last-admin safeguard. | Admins can assign administrator access; periodic review is required. |
| Password disclosure or database theft | Random salted PBKDF2-HMAC-SHA-256 hashes; no plaintext password storage; new/reset users must change temporary passwords. | No MFA, identity federation, e-mail recovery, or shared rate limiting. Administrators must transfer temporary credentials securely. |
| Forged or invalid control writes | SQLAlchemy bound parameters, field validation, database constraints, XSRF/CORS defaults enabled. | App and runtime still need patching and a correctly configured proxy. |
| Denial of service or brute-force attempts | Expensive password hashing, bounded user inputs, connection timeout, Compose service health checks. | No distributed request throttling, WAF, high availability, or capacity test. |
| Unauthorized evidence disclosure | No file upload or file-serving feature; evidence stored as references only. | References and notes can still disclose internal information; database access remains sensitive. |
| Undetected record changes | Actor/action/entity/timestamp audit events are written with mutations. | The database administrator can alter the audit table; no external immutable audit sink. |
| Database loss or accidental deletion | PostgreSQL named volume persists across app container restarts; runbook documents logical backups. | A volume is not a backup; operators must protect backups and test restoration. |
| Misleading compliance score or mapping | Score formula is documented and described as decision support; sample data is explicitly illustrative. | Owners must validate mapping, evidence, applicability, and conclusions. |

## Required deployment controls

1. Use TLS and an authenticated, restricted reverse proxy for non-local access.
2. Use unique high-entropy database and bootstrap secrets; keep them out of source control and rotate them under an approved process.
3. Limit database network access and protect backups with appropriate access and encryption.
4. Assign least-privilege roles; review and deactivate accounts regularly.
5. Test backup restoration and monitor application/database health and logs.
6. Do not store evidence files, credentials, or sensitive personal data in the app.

## Known gaps

No SSO/MFA, invitation workflow, self-service recovery, distributed login throttling, external append-only audit service, load/performance validation, multi-tenant data isolation, or high-availability deployment is included. The target of fewer than 1,000 registered users is not a performance guarantee.
