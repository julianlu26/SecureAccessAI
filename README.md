# SecureAccessAI (SP1 + SP3)

Flask-based backend for Sprint 1 through Sprint 3 deliverables:
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

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout` (Bearer token required)
- `GET /api/auth/me` (Bearer token required)
- `GET /api/admin/dashboard` (requires `admin:read` permission)
- `GET /api/admin/security-events` (requires `admin:read` permission)
- `POST /api/rbac/assign-role` (requires `rbac:assign_role` permission)

## Documentation

- API details: `Documentation/API_Documentation_SP1_SP2.md`
- UML class diagram: `Documentation/SP1_SP2_UML_Class_Diagram.md`
- Secrets and deployment notes: `Documentation/Deployment_and_Secrets.md`
- Security test scenarios and runtime config: `Documentation/Security_Test_Scenarios_and_Runtime_Config.md`
- Threat simulation assumptions and monitoring outputs: `Documentation/Threat_Simulation_Assumptions_and_Monitoring.md`
- Week 11 verification specs: `Documentation/Week11_Activity1_Software_Testing_Verification.md`

## Test

```bash
pytest -q
```
