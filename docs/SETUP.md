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

3. Check service readiness using `docker compose ps` and inspect logs with `docker compose logs -f grc-dashboard`.
4. Open `http://127.0.0.1:8501`; enter the bootstrap token and create the first workspace administrator.
5. Add accounts to the current workspace and assign roles according to least privilege.

Compose persists PostgreSQL data in the `grc_postgres_data` named volume. Alembic applies pending schema migrations during app startup. The dashboard port binds to loopback only. For use by remote people, put the app behind an HTTPS reverse proxy with appropriate access controls and a firewall; do not publish the raw app port to the public internet. Configure `BOOTSTRAP_ADMIN_TOKEN` before first run. Once the first user exists, the first-run route is no longer available.

## Workspaces, roles, and data handling

- A deployment can host multiple organizations. Each organization has isolated control data, members, groups, audit events, control history, and vulnerability-triage status.
- An account can join multiple workspaces and can have a different direct role in each. Use the organization selector to switch only among active memberships.
- **Viewer:** read and export that workspace's control data.
- **Editor:** viewer capabilities plus create/update controls and update that workspace's threat triage.
- **Administrator:** editor capabilities plus delete controls and manage workspace members, groups, organizations, and audit history.
- Groups can grant viewer or editor access only. Administrator permissions must be granted directly to a workspace membership. Each workspace must retain at least one active direct administrator.

Passwords must be at least 12 characters. Store only evidence references, not evidence files or credentials. Account changes should be followed by role review and, where needed, account deactivation.

New accounts must replace their temporary password before opening the dashboard. Administrators can set a temporary password for an account; communicate it through an approved secure channel and ask the account owner to choose a new password at first sign-in.

## Risk and public intelligence

Likelihood and impact are analyst-entered values from 1 to 5; their product is a 1–25 inherent-risk score. Residual risk is a separate analyst-entered rating. Dashboard recommendations are deterministic guidance, not legal or compliance advice.

The Threat intelligence page retrieves the public [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [CISA advisories RSS](https://www.cisa.gov/cybersecurity-advisories/all.xml), with a one-hour in-memory cache. A KEV entry does not mean the organization's systems are affected. Verify products and versions against the organization's own inventory; then record analyst triage in the active workspace. Feed retrieval is not background monitoring or a real-time guarantee.

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
