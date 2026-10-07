# Northstar Cybersecurity GRC Workspace

A single-organization governance, risk, and compliance workspace for a small team. Maintain a shared security-control register, assign owners and remediation dates, record evidence references, review risk priorities, and export filtered reports.

> **Data protection:** This application is not a certified GRC or document-management platform. Do not upload sensitive evidence files or regulated personal data. Store only approved evidence references and deploy behind HTTPS on a restricted network.

## What it does

- Role-based accounts: **administrator**, **editor**, and **viewer**
- Persistent controls, framework mappings, owners, maturity, risks, dates, evidence references, and notes
- Executive metrics and domain/framework summaries based on the active filters
- Control create, edit, and administrator-only delete workflows
- Evidence/remediation register and CSV export
- Spreadsheet-formula neutralization for untrusted text in CSV exports
- User management, password changes, administrator safeguards, and a control/account audit trail
- PostgreSQL deployment through Docker Compose; SQLite for local development and tests

The app is designed for a single organization with fewer than 1,000 registered users. That is a target usage profile, not a load-test or availability guarantee. The Compose deployment runs one Streamlit application instance with one PostgreSQL database.

## Quick start: local development

Requires Python 3.12 or newer.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Set a local database URL and a one-time first-administrator bootstrap token in PowerShell. Generate the token with a cryptographically secure random generator:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$bootstrapToken = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
$env:BOOTSTRAP_ADMIN_TOKEN = $bootstrapToken
$env:DATABASE_URL = 'sqlite:///./data/grc_dashboard.db'
Write-Host "Bootstrap token (keep private; enter it once in the setup screen): $bootstrapToken"
streamlit run app.py
```

On the first visit, enter the bootstrap token printed in the terminal to create the first administrator. Treat it as a secret; do not paste it into chat or commit it. The token is needed only until an account has been created. Subsequent users are provisioned by an administrator.

## Docker Compose: shared PostgreSQL

1. Generate two independent 64-character secrets and write them to `.env`:

   ```powershell
   $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
   $bytes = New-Object byte[] 32
   $rng.GetBytes($bytes)
   $dbPassword = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
   $rng.GetBytes($bytes)
   $bootstrapToken = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
   @("POSTGRES_PASSWORD=$dbPassword", "BOOTSTRAP_ADMIN_TOKEN=$bootstrapToken") |
     Set-Content -Encoding ascii .env
   Write-Host "Bootstrap token (keep private; enter it once in the setup screen): $bootstrapToken"
   ```

   `.env` is git-ignored. Never commit it or share the token.
2. Start the app:

   ```powershell
   docker compose up --build -d
   ```

4. Open `http://127.0.0.1:8501` and complete first-administrator setup with the bootstrap token.
5. Create named accounts with the minimum role needed for each person's work.

The dashboard port is bound to localhost by default. For remote access, use a hardened HTTPS reverse proxy and firewall; do not expose the unauthenticated Streamlit port directly to the internet. See [docs/SETUP.md](docs/SETUP.md) and [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Roles

| Role | Read and export | Create / edit controls | Delete controls | Manage users and audit |
|---|---:|---:|---:|---:|
| Viewer | Yes | No | No | No |
| Editor | Yes | Yes | No | No |
| Administrator | Yes | Yes | Yes | Yes |

Every account starts with a password of at least 12 characters. Passwords are salted and derived with PBKDF2-HMAC-SHA-256. Newly created and administrator-reset accounts must change their temporary password before reaching the dashboard. Role changes and password updates invalidate existing sessions on their next request; users sign in again.

## Project report

Read the print-ready report at [docs/PROJECT_REPORT.html](docs/PROJECT_REPORT.html). It includes the architecture infographic, entity/table descriptions, workflows, role matrix, risk-scoring explanation, example records, security controls, deployment model, and limitations. Open it in a browser and use **Print → Save as PDF** for a shareable report.

## Quality checks

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
black --check .
```

See [docs/VERIFICATION_REPORT.md](docs/VERIFICATION_REPORT.md) for the latest local verification evidence.

## Repository map

```text
app.py                         Streamlit application and role-aware UI
src/grc_dashboard/data.py      Demonstration controls used to seed an empty register
src/grc_dashboard/store.py     Validation, persistence, account lifecycle, and audit log
src/grc_dashboard/security.py  Password hashing and role permission checks
src/grc_dashboard/risk_engine.py  Maturity and risk calculations
migrations/                     Alembic schema migrations applied on app startup
tests/                         Risk, persistence, and access-control tests
docs/PROJECT_REPORT.html      Print-ready project report and infographic
```

## Important limits

- This is a small-team operational starter, not a substitute for a mature enterprise GRC system, identity provider, or certified compliance service.
- Authentication is application-managed; there is no SSO, MFA, invitation email, or self-service password reset. Administrators create accounts and can set a temporary password reset; users must change it before using the app.
- Evidence is stored as a reference only. Evidence files stay in the organization's approved document repository.
- The included controls are illustrative starter data. Framework mappings need review against the applicable official standard and the organization's scope.
- Risk scores are decision support. They do not establish legal compliance or certification.
- Before production use, configure TLS, backups and restore tests, monitoring, access restrictions, secrets rotation, and an organizational incident response process.

## License

MIT. See [LICENSE](LICENSE).
