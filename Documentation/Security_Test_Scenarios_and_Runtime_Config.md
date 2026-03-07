# Security Test Scenarios and Runtime Configuration (SCRUM-22)

This document defines the Sprint 3 security test scenarios and the runtime configuration needed to execute them consistently.

## Runtime Configuration

The following runtime variables control the security behavior of the authentication flow:

| Variable | Default | Purpose |
|---|---|---|
| `LOGIN_RATE_LIMIT_COUNT` | `5` | Maximum login attempts allowed within the configured rate-limit window. |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | `60` | Time window used by the rate limiter. |
| `LOGIN_FAILURE_THRESHOLD` | `3` | Number of failed attempts before temporary blocking is triggered. |
| `LOGIN_FAILURE_WINDOW_MINUTES` | `15` | Rolling window used for failed-attempt threshold checks. |
| `RISK_IP_LOOKBACK_HOURS` | `24` | Lookback window used to compare successful logins from different IP addresses. |

## Recommended Test Setup

- Use a fresh database or in-memory test database.
- Reset the in-memory rate limiter between test runs.
- Send `X-Forwarded-For` headers to simulate different client IP addresses.
- Use one admin account and one normal user account for protected-endpoint checks.

## Security Test Scenarios

| Scenario ID | Scenario | Expected Result |
|---|---|---|
| `SEC-01` | Valid login from known IP | Login succeeds and returns a low-risk assessment. |
| `SEC-02` | Invalid password attempt | Login fails with `401` and records a failed security event. |
| `SEC-03` | Repeated failed attempts from same IP | Threshold is reached and subsequent login attempt returns `403`. |
| `SEC-04` | Excessive login attempts in short time window | Rate limiter returns `429` with `rate_limited=true` in risk signals. |
| `SEC-05` | Successful login from a new IP after previous success | Login succeeds but returns elevated risk with `ip_change_detected=true`. |
| `SEC-06` | Access admin-only security event feed as non-admin | Request is denied with `403 Forbidden`. |
| `SEC-07` | Access admin security event feed as admin | Request succeeds and returns recent security events. |
| `SEC-08` | Logout then call protected endpoint with same token | Token is rejected because the session is revoked. |

## Manual Verification Steps

1. Register the first user and log in as admin.
2. Trigger failed login attempts from a fixed IP until the failure threshold is reached.
3. Trigger additional attempts from the same IP to confirm `429` rate limiting.
4. Perform a successful login from a different IP and inspect the returned risk signals.
5. Call `GET /api/admin/security-events` and verify that the expected events appear in reverse chronological order.

## Automated Coverage

Current automated tests cover:
- normal login flow
- logout token revocation
- failed-attempt threshold blocking
- rate limiting behavior
- IP-change risk detection and security event feed visibility
