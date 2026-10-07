# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Added organization-isolated workspaces, membership roles, group-based viewer/editor access, and workspace administration
- Added analyst-entered likelihood/impact risk scoring, control history, remediation guidance, and expanded dashboard metrics
- Added official CISA KEV/advisory feeds with bounded retrieval, source provenance, caching, and workspace-specific analyst triage
- Added migration backfill and partial-startup recovery coverage, plus cross-workspace isolation tests
- Added persistent PostgreSQL/SQLite storage, versioned migrations, and control CRUD
- Added least-privilege viewer/editor/administrator accounts, first-run token protection, and audit events
- Added temporary-password lifecycle and administrator account reset flow
- Added spreadsheet-formula neutralization to CSV exports
- Added print-ready architecture and project report with tables and infographic
- Added Docker Compose PostgreSQL deployment and operations/security guides
- Upgraded vulnerable Streamlit and Pillow dependencies; added SQLAlchemy, psycopg, and Alembic
- Improved repository front door and project metadata
- Added professional documentation and architecture decision records
- Added stronger validation and CI workflow structure
- Added case-study and demo assets

## [1.0.0] - 2026-10-07

### Added
- Initial GRC dashboard MVP
- Framework mapping for NIST CSF 2.0, ISO 27001 Annex A, NIS2, and GDPR
- Risk scoring and evidence tracking features
- Streamlit-based user interface and dashboard views
- Test suite for key scoring and summary functions
