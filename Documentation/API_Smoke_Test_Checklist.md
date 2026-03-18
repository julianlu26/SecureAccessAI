# API Smoke Test Checklist

This checklist supports quick final verification before demo or submission.

## Authentication

- [ ] `POST /api/auth/register` creates a new user successfully
- [ ] `POST /api/auth/login` returns an access token for valid credentials
- [ ] `POST /api/auth/logout` revokes the current session token
- [ ] `GET /api/auth/me` returns the authenticated user profile

## RBAC and Admin Access

- [ ] Non-admin users are blocked from admin endpoints with `403`
- [ ] Admin users can call `GET /api/admin/dashboard`
- [ ] Admin users can call `GET /api/admin/security-events`
- [ ] Admin users can call `GET /api/admin/audit-logs`
- [ ] Admin users can call `GET /api/admin/risk-summary`
- [ ] Authorized users can call `POST /api/rbac/assign-role`

## Security Monitoring

- [ ] Repeated failed logins raise the failed-attempt count
- [ ] Threshold blocking returns the expected error response
- [ ] Rate limiting returns `429` when the window is exceeded
- [ ] New IP login produces an elevated risk score

## Runtime and Delivery

- [ ] `GET /health` returns a healthy response
- [ ] `docker compose config` is valid
- [ ] README and supporting documentation links are present
