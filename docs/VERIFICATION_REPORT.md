# Verification report

**Verification date:** 2026-10-07
**Scope:** Northstar GRC application, SQLite-backed tests, database migrations, and runtime dependency set.

## Automated checks

| Check | Exact command | Result |
|---|---|---|
| Tests | `D:\Cybersecurity Project\.venv\Scripts\python.exe -m pytest -q` | **Passed:** 13 tests in 24.57 seconds. |
| Lint | `D:\Cybersecurity Project\.venv\Scripts\python.exe -m ruff check .` | **Passed:** All checks passed. |
| Formatting | `D:\Cybersecurity Project\.venv\Scripts\python.exe -m black --check .` | **Passed:** 13 files unchanged. |
| Dependency audit | `D:\Cybersecurity Project\.venv\Scripts\pip-audit.exe -r requirements.txt -r requirements-dev.txt` | **Passed:** No known vulnerabilities found across runtime and development dependencies. |
| Compose YAML syntax | `& 'D:\Cybersecurity Project\.venv\Scripts\python.exe' -c "import yaml; yaml.safe_load(open('docker-compose.yml', encoding='utf-8')); print('docker-compose.yml parses as YAML')"` | **Passed:** YAML parsed successfully. |
| Docker image build | GitHub Actions CI: `docker build --tag northstar-grc:ci .` | **Passed:** CI run [37571507321](https://github.com/Huzaifa-Amin/cybersecurity-grc-dashboard/actions/runs/37571507321). |
| GitHub security workflows | CodeQL Analysis and dependency scan | **Passed:** Security run [37571507145](https://github.com/Huzaifa-Amin/cybersecurity-grc-dashboard/actions/runs/37571507145). |

The test suite includes Streamlit `AppTest` coverage for first-administrator setup, administrator and viewer sign-in, required temporary-password replacement, and role-specific UI boundaries. Store tests cover migrations, sample-data seeding, control CRUD/audit entries, validation, password hashing/reset, session-version changes, role behavior, and administrator safeguards. CSV tests verify formula-like input is exported as text.

## Runtime startup check

Command:

```powershell
$env:DATABASE_URL = '<temporary SQLite database URL>'
$env:BOOTSTRAP_ADMIN_TOKEN = '<test-only token>'
python -m streamlit run app.py --server.headless true --server.port 8502
```

Result: **Passed.** The app started at `http://127.0.0.1:8502`; `GET /_stcore/health` returned **HTTP 200**. The first-administrator setup page rendered in a browser. The temporary database and its SQLite sidecar files were removed afterward. Local Streamlit is configured to bind to loopback and usage telemetry is disabled.

## Deployment validation boundary

The Docker CLI is not installed in the local development environment, so Docker Compose interpolation, PostgreSQL startup, and PostgreSQL-backed application behavior were **not run locally**. The container image build did pass in GitHub Actions, but this does not validate Compose orchestration, database connectivity, backups/restores, or production deployment. Validate those in an environment with Docker Compose and PostgreSQL before team use.

## Known scope limits

- The fewer-than-1,000-user profile is a design target, not a tested throughput or availability guarantee.
- The supplied verification uses SQLite; exercise migrations, backups/restores, and expected concurrent use against the actual PostgreSQL host before launch.
- This project has no SSO/MFA, e-mail invitations or self-service password recovery, distributed login throttling, immutable external audit sink, evidence file store, multi-tenant isolation, or high availability.
- No independent penetration test, accessibility audit, or production load test was performed.
- Sample controls and framework references are illustrative and require organizational review.

This report records checks run in the current workspace; it is not a compliance attestation or production certification.
