# Troubleshooting

## Streamlit does not start

Confirm Python 3.12+, the active virtual environment, and application dependencies:

```powershell
python -m pip install -r requirements.txt
$env:DATABASE_URL = 'sqlite:///./data/grc_dashboard.db'
$env:BOOTSTRAP_ADMIN_TOKEN = '<operator-generated-token>'
streamlit run app.py
```

Check the startup output for syntax/import errors and confirm the configured working directory is the repository root.

## Database initialization or connection fails

- Local development: check the `DATABASE_URL` spelling and that the process can create the `data` directory and SQLite file.
- Docker Compose: inspect `docker compose ps`, `docker compose logs database`, and `docker compose logs grc-dashboard`.
- Confirm `.env` contains both required, non-placeholder values. PostgreSQL passwords should be hexadecimal as documented so the URL remains valid.
- Do not delete a production database or volume to resolve a connection issue. Take a backup and diagnose first.

## First administrator setup is locked

The first account can only be created when the database has no user records and the app process has `BOOTSTRAP_ADMIN_TOKEN` set. If accounts already exist, sign in as an administrator and create or reactivate an account through user management. If all administrator accounts have been lost, use a controlled database-administrator recovery procedure; do not add a public setup bypass.

## Sign-in fails

Check the username spelling and account status with an administrator. Passwords are case-sensitive. If a role or password changed, sign in again because existing sessions are invalidated on their next request. There is no e-mail password-reset feature; an administrator must provision a replacement account.

## Control form rejects a value

Check that required labels are filled, the control ID is unique, the score is an integer from 0 through 100, the selected status/risk is valid, and the due date is valid. The application displays validation errors next to the form. Evidence and notes are limited to 4,000 characters each.

## Dashboard metrics or register look empty

Review the framework/domain/risk/search filters in the sidebar. Metrics follow the filtered set. On a genuinely new database, starter controls are seeded once; deleting all controls afterward leaves the register empty on restart.

## Tests, lint, or CI fail

Run checks from the repository root:

```powershell
python -m pytest -q
ruff check .
black --check .
```

Inspect the first failing test or CI step. The automated persistence tests use temporary SQLite databases and do not replace validation against the intended PostgreSQL deployment.

## Sensitive diagnostics

Before sharing logs, screenshots, or database URLs, remove credentials, bootstrap tokens, personal information, and evidence contents. Report suspected vulnerabilities through the private process in [SECURITY.md](../SECURITY.md), not a public issue.
