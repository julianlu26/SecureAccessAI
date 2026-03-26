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
cp .env.example .env
# Set SECRET_KEY to a strong value before starting
python run.py
```

Server runs on `http://127.0.0.1:5000`.

## Quick Start (Docker)

```bash
cp .env.example .env
# Set SECRET_KEY before starting
# Optionally set BOOTSTRAP_ADMIN_EMAIL for the first admin account
# Only set TRUST_PROXY_HEADERS=true when running behind a trusted reverse proxy
docker compose up --build
```

## Demo UI

- `GET /` opens the browser demo page
- `GET /demo` opens the same demo page
- The page can register users, login, call `/me`, assign roles, and load admin endpoints

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

## Security Configuration Notes

- The application will refuse to start with a default `SECRET_KEY` outside test mode.
- `TRUST_PROXY_HEADERS=true` should only be enabled behind a trusted proxy or gateway.
- `BOOTSTRAP_ADMIN_EMAIL` can be used to explicitly define which first account receives the admin role.

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
- Release tag v1.0.0 created for the final classroom snapshot
