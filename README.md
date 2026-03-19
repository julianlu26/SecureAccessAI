# SecureAccessAI (SP1 + SP3)

Flask-based backend for the final SecureAccessAI classroom release:
- Core authentication (register/login/logout/me)
- Password hashing with bcrypt
- Session token validation with JWT + persisted session records
- RBAC models (User, Role, Permission)
- Authorization middleware and permission-protected endpoints
- Role assignment API
- IP-based login event logging
- Login attempt threshold blocking and rate limiting
- MVP anomaly detection and threat scoring

## Quick Start (Local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Server runs on `http://127.0.0.1:5000`.

## Quick Start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

## API Summary

- `GET /health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout` (Bearer token required)
- `GET /api/auth/me` (Bearer token required)
- `GET /api/admin/dashboard` (requires `admin:read` permission)
- `GET /api/admin/audit-logs` (requires `admin:read` permission)
- `GET /api/admin/risk-summary` (requires `admin:read` permission)
- `GET /api/admin/security-events` (requires `admin:read` permission)
- `POST /api/rbac/assign-role` (requires `rbac:assign_role` permission)

## Documentation

- API details: `Documentation/API_Documentation_SP1_SP2.md`
- UML class diagram: `Documentation/SP1_SP2_UML_Class_Diagram.md`
- Architecture notes: `Documentation/Architecture_Notes_SP1_SP2.md`
- Bilingual architecture overview: `Documentation/Bilingual_Architecture_Overview.md`
- Final UML class diagram: `Documentation/Final_UML_Class_Diagram.md`
- Secrets and deployment notes: `Documentation/Deployment_and_Secrets.md`
- Docker deployment runbook: `Documentation/Docker_Deployment_Runbook.md`
- Security test scenarios and runtime config: `Documentation/Security_Test_Scenarios_and_Runtime_Config.md`
- Threat simulation assumptions and monitoring outputs: `Documentation/Threat_Simulation_Assumptions_and_Monitoring.md`
- Submission readiness checklist: `Documentation/Submission_Readiness_Checklist.md`
- Final documentation index: `Documentation/Final_Project_Documentation_Index.md`
- Reflection input materials: `Documentation/Reflection_Input_Materials.md`
- Week 11 verification specs: `Documentation/Week11_Activity1_Software_Testing_Verification.md`

## Test

```bash
pytest -q
```


## Release Snapshot

- Release tag: `v1.0.0`
- CI workflow validates dependencies, compose configuration, and pytest coverage
- Current scope includes authentication, RBAC, threat simulation, and audit/risk summary endpoints


## Assessment Artefacts

- Assessment 2 project report and reflection report prepared for submission
- Assessment 3 presentation PDF and speaking notes prepared for demonstration
- Release tag  created for the final classroom snapshot
