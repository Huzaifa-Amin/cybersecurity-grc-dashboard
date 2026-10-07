# Security policy

## Scope and use

Northstar is a small-organization GRC workspace starter. It is not a certified compliance platform, document-management system, identity provider, or security operations service. Do not store evidence files, secrets, or regulated personal information in control notes or evidence references.

Before operational use, deploy behind HTTPS and restrict network access, keep database and bootstrap secrets outside source control, configure protected backups, test restores, review assigned roles, and validate the framework mappings and data-retention requirements for your organization.

## Supported versions

The latest version on the default branch is the only version currently maintained.

## Reporting a vulnerability

Please do not report suspected vulnerabilities in public issues. Use GitHub's private vulnerability reporting for this repository: <https://github.com/Huzaifa-Amin/cybersecurity-grc-dashboard/security/advisories/new>.

Include the affected version, impact, reproduction steps, and any relevant sanitized logs. Do not include real credentials, personal information, production evidence, or secrets in a report.

## Security controls and limitations

The app implements named application-managed accounts, PBKDF2-HMAC-SHA-256 password hashes, role checks, bootstrap-token-protected first-admin setup, mandatory changes of temporary passwords, validation, parameterized SQLAlchemy persistence, Alembic schema migrations, PostgreSQL for Compose, and application audit events.

It does not implement SSO, MFA, invitation e-mail, self-service recovery, shared rate limiting, immutable external audit storage, or evidence file storage. These limitations must be evaluated against organizational requirements before deployment. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
