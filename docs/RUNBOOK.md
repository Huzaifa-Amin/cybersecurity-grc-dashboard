# Operations runbook

## Service overview

The deployment contains one Streamlit app and one PostgreSQL database. The app uses application-managed accounts and server-side session state. Alembic applies pending schema upgrades during app startup. Compose binds the app to `127.0.0.1:8501` by default and persists PostgreSQL data in the `grc_postgres_data` named volume.

## Start and inspect

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f grc-dashboard
docker compose logs -f database
```

The app health check is served at `/_stcore/health`. A database health check uses `pg_isready`. The app waits for the database health check before startup.

## Accounts and access

- First-run account creation requires the operator-configured `BOOTSTRAP_ADMIN_TOKEN`.
- Administrators create named accounts and select the least-privilege role: viewer, editor, or administrator.
- Newly created or password-reset accounts must change their temporary password before accessing the workspace. Administrators can reset other accounts; send the temporary credential only through an approved secure channel.
- Editors create and update controls; only administrators can delete controls.
- Administrators can deactivate accounts and review recent audit events.
- Users change their own password from the account panel. Password or role changes invalidate that account's existing sessions on their next request.
- At least one active administrator must remain.

Never share accounts. Do not send passwords or bootstrap tokens through issue reports or logs.

## Backup and restore

Create a logical PostgreSQL backup:

```powershell
docker compose exec -T database pg_dump -U grc_dashboard grc_dashboard > .\grc-dashboard-backup.sql
```

Protect the backup as sensitive organizational information and copy it to a separate, access-controlled location. Test restore procedures on a separate database before relying on backups. The persistent Docker volume is not a backup.

For a clean PostgreSQL database restore:

```powershell
Get-Content .\grc-dashboard-backup.sql -Raw |
  docker compose exec -T database psql -U grc_dashboard -d grc_dashboard
```

Use a maintenance window and verify the restored control count, accounts, and recent audit events. For local SQLite development, stop the app before taking a consistent file copy.

## Maintenance

- Monitor container health, application/database logs, free disk space, and dependency advisories.
- Apply reviewed dependency and base-image updates; rebuild and run the test suite before deploying.
- Review active administrators and account roles periodically; deactivate users who no longer need access.
- Rotate secrets using an approved process and verify database connectivity afterward.
- Test database backups and restore drills regularly.
- Keep the app behind TLS and network access controls for any non-local usage.

## Recovery and known boundaries

If the database is unavailable, the app displays a database initialization/access error rather than substituting demo data. Preserve logs while diagnosing the configured database and networking. If the database is lost, restore a verified backup; otherwise an empty database is initialized with starter controls and requires a new bootstrap token and first administrator.

This is a single-app-instance design and does not include high availability, automated migration tooling, SSO/MFA, a tamper-proof audit sink, evidence file storage, or capacity guarantees. The under-1,000-user profile is a target, not a measured service level.
