# Submission Readiness Checklist (SCRUM-26)

This checklist records the final integration checks completed before submission.

## Application Readiness

- `PASS` Flask application starts with configured environment variables.
- `PASS` Authentication flow supports register, login, logout, and token validation.
- `PASS` RBAC protection is enforced on admin and role-management endpoints.
- `PASS` Sprint 3 security controls cover IP logging, failed-attempt thresholding, rate limiting, and threat scoring.
- `PASS` Sprint 4 admin endpoints expose dashboard, security events, audit logs, and risk summaries.

## Test Readiness

- `PASS` Automated pytest suite covers SP1 through SP4 core flows.
- `PASS` Rate limiting, failed-attempt blocking, and IP-change risk scenarios are verified.
- `PASS` Admin dashboard and audit log access are validated for authorized users.

## Documentation Readiness

- `PASS` API documentation is present.
- `PASS` Deployment and secrets notes are present.
- `PASS` Security test scenarios and threat monitoring assumptions are present.
- `PASS` Week 11 verification specification list is present.

## Deployment Readiness

- `PASS` Dockerfile exists for containerized execution.
- `PASS` `docker-compose.yml` exists for local container orchestration.
- `PASS` `.env.example` lists required runtime variables.
- `PASS` GitHub Actions CI workflow runs pytest on push and pull request.

## Remaining Manual Checks Before Final Submission

- Confirm teammate-owned Sprint 4 documentation deliverables are merged.
- Review Jira issue statuses one final time.
- Capture any reflection notes required by the assessment rubric.

## Demo Readiness

- PASS Assessment 3 slide order has been drafted.
- PASS Speaker split is documented for both team members.
- PASS Demo Q and A notes are available for likely tutor questions.
