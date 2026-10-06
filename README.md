# Cybersecurity GRC Control & Evidence Dashboard

A beginner-friendly but portfolio-grade cybersecurity governance, risk, and compliance dashboard designed to show employers that you understand how security programs are governed in real organizations.

## Why this project matters

This project is built for the same hiring market that values:

- ISO 27001 and ISMS concepts
- NIST CSF 2.0 governance and risk control mapping
- NIS2 operational resilience expectations
- GDPR and privacy risk awareness
- Board-ready security reporting and evidence tracking

This is a strong fit for GRC, compliance, security governance, and cyber risk roles across Europe and the United States.

## Project goals

- Demonstrate a working governance and control register
- Show how controls map to major frameworks
- Present risk and evidence in a board-ready dashboard
- Provide a professional portfolio project with documentation, CI, tests, and Docker setup

## Architecture diagram

```text
User / Hiring Manager
        |
        v
Streamlit dashboard (Python)
        |
        v
GRC data model + risk engine
        |
        +--> Control data set
        +--> NIST CSF 2.0 mapping
        +--> ISO 27001 Annex A mapping
        +--> NIS2 / GDPR controls
        +--> Risk scoring and prioritization
```

## Demo features

- Executive KPI overview
- Control mapping across frameworks
- Risk register with priority scoring
- Ownership and evidence tracking
- Status filtering by framework and domain
- Board-facing summary text for non-technical stakeholders

## Tech stack

- Python 3.12
- Streamlit
- Pandas
- SQLite-ready data model structure
- Pytest
- GitHub Actions
- Docker

## Local setup

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

## Docker

```bash
docker build -t grc-dashboard .
docker run -p 8501:8501 grc-dashboard
```

## Framework mapping

This project intentionally maps controls to commonly used governance frameworks, including:

- NIST CSF 2.0
- ISO 27001 Annex A
- NIS2
- GDPR

## Threat model summary

This is a portfolio project and not a production SOC platform, but it still reflects realistic security concerns:

- unauthorized access to evidence or policy records
- stale or incomplete control data
- misalignment between risk owners and evidence owners
- weak governance around exceptions and remediation tracking

## Why employers care

This project shows that you can:

- understand governance and control design
- translate technical controls into business language
- show evidence and accountability in a clear way
- map compliance requirements to risk management practice

## License

MIT

## Repository structure

```text
.
├── app.py
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── requirements.txt
├── src/
│   └── grc_dashboard/
│       ├── __init__.py
│       ├── data.py
│       └── risk_engine.py
├── tests/
│   └── test_risk_engine.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── INTERVIEW_GUIDE.md
│   └── THREAT_MODEL.md
├── .github/
│   └── workflows/
│       └── ci.yml
└── docker-compose.yml
```
