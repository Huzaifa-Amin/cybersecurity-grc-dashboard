# Security policy

## Scope and use

Northstar is a small-team, multi-organization GRC workspace. Organization access is enforced at the data-service layer; user accounts may have distinct roles in multiple workspaces, and groups can grant viewer/editor but not administrator. The app is not a certified compliance platform, document-management system, identity provider, asset inventory, or security operations service. Public CISA feed entries are not evidence that an organization's systems are exposed. Do not store evidence files, secrets, or regulated personal information in control notes or evidence references.

Before operational use, deploy behind HTTPS and restrict network access, keep database and bootstrap secrets outside source control, configure protected backups, test restores, review assigned roles, and validate the framework mappings and data-retention requirements for your organization.

## Supported versions

The latest version on the default branch is the only version currently maintained.

## Reporting a vulnerability

Please do not report suspected vulnerabilities in public issues. Use GitHub's private vulnerability reporting for this repository: <https://github.com/Huzaifa-Amin/cybersecurity-grc-dashboard/security/advisories/new>.

Include the affected version, impact, reproduction steps, and any relevant sanitized logs. Do not include real credentials, personal information, production evidence, or secrets in a report.

## Security controls and limitations

The app implements named application-managed accounts, PBKDF2-HMAC-SHA-256 password hashes, workspace membership and role checks, group-based viewer/editor permissions, bootstrap-token-protected first-admin setup, mandatory changes of temporary passwords, validation, parameterized SQLAlchemy persistence, Alembic migrations, organization-scoped PostgreSQL/SQLite persistence, audit and control history, and bounded public CISA feed retrieval with source provenance.

It does not implement SSO, MFA, invitation e-mail, self-service recovery, distributed rate limiting, immutable external audit storage, asset inventory/exposure matching, or evidence file storage. These limitations must be evaluated against organizational requirements before deployment. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
