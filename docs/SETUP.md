# Setup and deployment guide

## Requirements

- Python 3.12 or newer for local development
- Docker Engine and Docker Compose v2 for the shared PostgreSQL deployment
- A supported browser

## Local development with SQLite

From PowerShell at the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:DATABASE_URL = 'sqlite:///./data/grc_dashboard.db'
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$bootstrapToken = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
$env:BOOTSTRAP_ADMIN_TOKEN = $bootstrapToken
Write-Host "Bootstrap token (keep private; enter it once in the setup screen): $bootstrapToken"
streamlit run app.py
```

Keep the generated bootstrap token available for initial setup. On the first app visit, enter it once to create the first administrator. Do not paste it into chat or commit it. The operator must configure a new token if the database is deleted and reset. This database is local to the app host; it is not shared between hosts.

## Shared deployment with PostgreSQL

1. Create `.env` with two independent random hexadecimal secrets:

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

   `.env` is git-ignored. Do not commit the file or share its secrets.
2. Start the application:

   ```powershell
   docker compose up --build -d
   ```

4. Check service readiness using `docker compose ps` and inspect logs with `docker compose logs -f grc-dashboard`.
5. Open `http://127.0.0.1:8501`; enter the bootstrap token and create an administrator.
6. Add named user accounts and assign viewer, editor, or administrator according to least privilege.

Compose persists PostgreSQL data in the `grc_postgres_data` named volume. Alembic applies pending schema migrations during app startup. The dashboard port binds to loopback only. For use by remote people, put the app behind an HTTPS reverse proxy with appropriate access controls and a firewall; do not publish the raw app port to the public internet. Configure `BOOTSTRAP_ADMIN_TOKEN` before first run. Once the first user exists, the first-run route is no longer available.

## Hosted deployment with Render

GitHub hosts this repository and its static project pages; it does not run the Streamlit server or provide its database. The repository includes a Render Blueprint (`render.yaml`) for a Docker web service and a managed PostgreSQL database. Provisioning the Blueprint requires a Render account, GitHub authorization, and a billing method for the configured service/database plans. Review the current plan prices and region availability in Render before creating resources; this configuration can incur ongoing charges.

1. Sign in to Render and select **New → Blueprint**.
2. Connect the public `Huzaifa-Amin/cybersecurity-grc-dashboard` repository and select the `master` branch.
3. Review the proposed `northstar-grc` web service and `northstar-grc-db` PostgreSQL database, including plan prices, region, and networking; provision only if those choices are acceptable.
4. Wait for the first deployment and database migrations to complete. Open the deployed service URL and use the generated `BOOTSTRAP_ADMIN_TOKEN` from the service's environment settings to create the first administrator.
5. The deployed database is new and separate from any local SQLite database. Create a new hosted administrator account; local users and control records are not copied.
6. After the first administrator is created, remove the `BOOTSTRAP_ADMIN_TOKEN` environment variable from the hosted service and redeploy. Keep application access invite-only by creating named users in the admin panel and assigning least-privilege roles.
7. Before inviting users, verify sign-in, account creation, control updates, CSV export, database persistence across a service restart, and the provider's database backup/restore process. Review public access, TLS, secret rotation, monitoring, and incident response for your organization.

The Blueprint configures one app instance and PostgreSQL. It does not add SSO/MFA, multi-organization isolation, or a measured capacity guarantee. Protect the hosted service URL; the application is intended for one organization, and registered users may see the organization's shared GRC records according to their role. Do not place sensitive evidence files or regulated personal data in the app.

## Roles and data handling

- **Viewer:** read and export filtered control data.
- **Editor:** viewer capabilities plus create and update controls.
- **Administrator:** editor capabilities plus delete controls, user administration, and audit-log review.

Passwords must be at least 12 characters. Store only evidence references, not evidence files or credentials. Account changes should be followed by role review and, where needed, account deactivation.

New accounts must replace their temporary password before opening the dashboard. Administrators can set a temporary password for an account; communicate it through an approved secure channel and ask the account owner to choose a new password at first sign-in.

## Tests and quality tools

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
black --check .
```

For a production rollout, test the actual PostgreSQL target, verify backup restoration, review reverse-proxy and TLS configuration, and run a workload test appropriate to the expected concurrent usage. The repository's unit tests use temporary SQLite databases.

## Troubleshooting

- Database startup: check `DATABASE_URL`, PostgreSQL health, `.env` values, and `docker compose logs database`.
- First administrator setup is locked: ensure `BOOTSTRAP_ADMIN_TOKEN` is set in the app process and that no user row already exists.
- Port conflict: update the host side of the Compose mapping and access the corresponding local port.
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more help.
