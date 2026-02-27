# Week 11 - Activity 1: Software Testing Verification

This document lists SecureAccessAI project specifications for Assessment 2 verification.
Each specification has a one-line description.

| Spec ID | Project Specification | One-line Description |
|---|---|---|
| SAI-SPEC-01 | Modular Flask project architecture | The backend must use a modular Flask structure with separated models, services, routes, and middleware. |
| SAI-SPEC-02 | User entity and persistence | The system must store user profile/account data in a database-backed `User` model. |
| SAI-SPEC-03 | Password hashing (bcrypt) | User passwords must be hashed with bcrypt and never stored in plain text. |
| SAI-SPEC-04 | Registration API | The system must provide a registration endpoint with input validation and duplicate-email checks. |
| SAI-SPEC-05 | Login API | The system must provide a login endpoint that verifies credentials and returns an access token. |
| SAI-SPEC-06 | Session token lifecycle | The system must persist session tokens and support logout-based token revocation. |
| SAI-SPEC-07 | JWT token validation | Protected requests must validate JWT integrity, expiry, and session status before access is granted. |
| SAI-SPEC-08 | Role model | The system must represent user roles (for example `admin`, `user`) through a dedicated `Role` model. |
| SAI-SPEC-09 | Permission model | The system must represent access privileges through a dedicated `Permission` model. |
| SAI-SPEC-10 | RBAC role-permission mapping | The system must enforce authorization via role-to-permission relationships (RBAC). |
| SAI-SPEC-11 | Authorization middleware | Endpoints must be protected by middleware/decorators that check required permissions. |
| SAI-SPEC-12 | Policy engine abstraction | Authorization rules must be exposed through a policy interface to support future policy extensions. |
| SAI-SPEC-13 | Role assignment workflow | Authorized users must be able to assign roles through a secure RBAC management endpoint. |
| SAI-SPEC-14 | Admin-only endpoint control | Admin-only APIs must deny requests from authenticated users without required admin permissions. |
| SAI-SPEC-15 | Security-focused test coverage | Core authentication and authorization flows must be verified with automated tests. |
| SAI-SPEC-16 | UML and API technical documentation | The project must include UML and API docs that match implemented SP1/SP2 behavior. |
| SAI-SPEC-17 | IP logging (SP3 planned) | The system should record source IP metadata for security-relevant requests. |
| SAI-SPEC-18 | Rate limiting (SP3 planned) | The system should limit repeated requests to reduce brute-force and abuse risk. |
| SAI-SPEC-19 | Threat scoring (SP3 planned) | The system should calculate a risk score from anomaly and traffic signals. |
| SAI-SPEC-20 | Audit and behaviour analytics (SP4 planned) | The system should provide auditable logs and behaviour-based risk summaries for administrators. |

