# Reflection Input Materials (SCRUM-28)

This document captures concise reflection points that can be used in the final report or presentation.

## What Worked Well

- The project progressed in clear sprint increments with traceable Jira tasks.
- Core authentication and RBAC were implemented early, which reduced integration risk later.
- Security controls were introduced as measurable backend rules rather than vague future placeholders.
- Automated tests provided a stable verification baseline for each sprint.

## Challenges Encountered

- Two-person workload balancing required tighter separation between development and documentation tasks.
- Working with multiple workstations and separate contributor identities increased coordination overhead.
- Some delivery work had to be reframed from broad goals into smaller demonstrable backend increments.

## Key Technical Decisions

- Flask was kept modular to separate models, services, middleware, and routes.
- JWT plus persisted session records was used to support validation and revocation.
- Threat scoring was implemented as a rules-based MVP to keep the solution explainable and testable.
- Sprint 4 analytics was delivered through admin APIs and summaries before any advanced frontend dashboard work.

## What Could Be Improved

- Replace SQLite with a production-grade database.
- Add persistent distributed rate limiting for multi-instance deployments.
- Expand anomaly detection beyond IP and failed-attempt heuristics.
- Add richer frontend dashboards and visual reporting.

## Team Contribution Summary

- `YUAN LU`: backend implementation, security logic, integration, Jira progress updates
- `shang ma`: Docker/deployment documentation, final documentation package, reflection and runbook materials

## Communication Practices

- Weekly task review in Jira helped keep ownership visible.
- Git commit linking made contribution tracking more transparent.
- Splitting implementation and documentation work reduced overlap while keeping joint accountability.
