# Threat Simulation Assumptions and Monitoring Outputs (SCRUM-23)

This document records the assumptions behind the Sprint 3 threat simulation MVP and describes the expected monitoring outputs.

## Assumptions

- The application is behind a proxy or gateway that forwards client IP information through `X-Forwarded-For`.
- Authentication attacks are simulated at the login endpoint only.
- The current MVP uses rules-based detection rather than machine learning.
- A higher threat score indicates greater review priority, not an automatic incident declaration.
- SQLite is sufficient for classroom demonstration, but production monitoring should use a durable operational datastore.

## Detection Signals

| Signal | Description | Current Weight |
|---|---|---|
| `failed_attempt_burst` | Multiple failed attempts from the same IP/email within the failure window. | `35` |
| `repeated_failed_attempts` | Failed attempts exist but have not yet reached the hard threshold. | `5` per attempt, capped at `20` |
| `ip_change_detected` | Successful login comes from a different IP than the recent successful login history. | `30` |
| `rate_limited` | The login request exceeded the configured request-rate threshold. | `40` |

## Threat Score Interpretation

| Score Range | Interpretation |
|---|---|
| `0-20` | Low risk; expected or isolated behavior. |
| `21-50` | Medium risk; suspicious pattern worth reviewing. |
| `51-100` | High risk; repeated abuse or multiple concurrent signals. |

## Monitoring Output Source

Security monitoring output is currently exposed through:
- login responses with `risk_assessment`
- persisted `security_events` records
- admin endpoint `GET /api/admin/security-events`

## Example Security Event Output

```json
{
  "id": 4,
  "email": "lead@example.com",
  "ip_address": "10.0.0.31",
  "event_type": "login",
  "outcome": "success",
  "risk_score": 30,
  "detail": "new IP compared with recent successful login",
  "created_at": "2026-03-07T10:00:00"
}
```

## Expected Monitoring Patterns

- A single failed login should produce a low or medium risk event depending on count.
- Threshold-based lockout should produce `blocked` login events with elevated risk.
- Rate-limited requests should show the highest score contribution in the current MVP.
- A successful login from a new IP should remain successful but carry an elevated score for review.

## Known Limits of the Current MVP

- No persistent distributed rate limiting across multiple application instances.
- No geolocation, device fingerprinting, or ASN analysis.
- No dashboard visualization yet; monitoring is currently API-based.
- No background alerting pipeline; review is manual through admin APIs and logs.
