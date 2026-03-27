import pytest

from app import create_app
from app.config import Config
from app.services.security_service import RateLimiter


@pytest.fixture()
def client():
    RateLimiter.reset()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "JWT_EXPIRES_MINUTES": 30,
            "LOGIN_RATE_LIMIT_COUNT": 5,
            "LOGIN_RATE_LIMIT_WINDOW_SECONDS": 60,
            "LOGIN_FAILURE_THRESHOLD": 3,
            "LOGIN_FAILURE_WINDOW_MINUTES": 15,
            "RISK_IP_LOOKBACK_HOURS": 24,
            "TRUST_PROXY_HEADERS": True,
            "BOOTSTRAP_ADMIN_EMAIL": "lead@example.com",
            "MFA_ENABLED": True,
            "MFA_CODE_TTL_SECONDS": 300,
            "MFA_REQUIRE_SAME_IP": True,
            "SHOW_DEMO_MFA_CODE": True,
            "ADMIN_SHOW_FULL_PII": False,
        }
    )
    return app.test_client()


def _register(client, username, email, password):
    return client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )


def _start_login(client, email, password, ip_address=None):
    kwargs = {}
    if ip_address:
        kwargs["headers"] = {"X-Forwarded-For": ip_address}
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        **kwargs,
    )


def _verify_code(client, challenge_id, code, ip_address=None):
    kwargs = {}
    if ip_address:
        kwargs["headers"] = {"X-Forwarded-For": ip_address}
    return client.post(
        "/api/auth/verify-code",
        json={"challenge_id": challenge_id, "code": code},
        **kwargs,
    )


def _login(client, email, password):
    first = _start_login(client, email, password)
    payload = first.get_json() or {}
    if first.status_code != 200 or not payload.get("mfa_required"):
        return first
    return _verify_code(client, payload["challenge_id"], payload["demo_code"])


def _login_from_ip(client, email, password, ip_address):
    first = _start_login(client, email, password, ip_address=ip_address)
    payload = first.get_json() or {}
    if first.status_code != 200 or not payload.get("mfa_required"):
        return first
    return _verify_code(client, payload["challenge_id"], payload["demo_code"], ip_address=ip_address)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_sp1_register_and_login(client):
    reg = _register(client, "lead", "lead@example.com", "Pass1234!")
    assert reg.status_code == 201
    assert "admin" in reg.get_json()["roles"]

    challenge = _start_login(client, "lead@example.com", "Pass1234!")
    assert challenge.status_code == 200
    challenge_payload = challenge.get_json()
    assert challenge_payload["mfa_required"] is True
    assert len(challenge_payload["demo_code"]) == 6

    login = _verify_code(
        client,
        challenge_payload["challenge_id"],
        challenge_payload["demo_code"],
    )
    assert login.status_code == 200
    assert "access_token" in login.get_json()
    assert login.get_json()["risk_assessment"]["score"] == 0


def test_sp2_rbac_endpoint_restriction_and_role_assignment(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")

    lead_token = _login(client, "lead@example.com", "Pass1234!").get_json()["access_token"]
    peer_token = _login(client, "peer@example.com", "Pass1234!").get_json()["access_token"]

    denied = client.get("/api/admin/dashboard", headers=_auth_header(peer_token))
    assert denied.status_code == 403

    assign = client.post(
        "/api/rbac/assign-role",
        json={"email": "peer@example.com", "role": "admin"},
        headers=_auth_header(lead_token),
    )
    assert assign.status_code == 200

    granted = client.get("/api/admin/dashboard", headers=_auth_header(peer_token))
    assert granted.status_code == 200


def test_logout_revokes_session_token(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    token = _login(client, "lead@example.com", "Pass1234!").get_json()["access_token"]

    out = client.post("/api/auth/logout", headers=_auth_header(token))
    assert out.status_code == 200

    me = client.get("/api/auth/me", headers=_auth_header(token))
    assert me.status_code == 401


def test_sp3_failure_threshold_blocks_repeated_failed_logins(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")

    first = _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.10")
    second = _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.10")
    third = _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.10")

    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 403
    assert third.get_json()["risk_assessment"]["score"] >= 35
    assert third.get_json()["risk_assessment"]["signals"]["failed_attempt_burst"] is True


def test_sp3_rate_limiter_returns_429(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")

    for _ in range(5):
        response = _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.20")
        assert response.status_code in (401, 403)

    blocked = _start_login(client, "lead@example.com", "Pass1234!", ip_address="10.0.0.20")
    assert blocked.status_code == 429
    assert blocked.get_json()["risk_assessment"]["signals"]["rate_limited"] is True


def test_sp3_ip_change_generates_risk_signal_and_security_event_feed(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")

    first_login = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.30")
    assert first_login.status_code == 200
    first_token = first_login.get_json()["access_token"]

    second_login = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.31")
    assert second_login.status_code == 200
    assert second_login.get_json()["risk_assessment"]["score"] >= 30
    assert second_login.get_json()["risk_assessment"]["signals"]["ip_change_detected"] is True

    events = client.get("/api/admin/security-events", headers=_auth_header(first_token))
    assert events.status_code == 200
    assert len(events.get_json()["events"]) >= 2


def test_sp4_dashboard_risk_summary_and_audit_logs(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")

    lead_login = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.40")
    lead_token = lead_login.get_json()["access_token"]

    _start_login(client, "peer@example.com", "wrong-password", ip_address="10.0.0.41")
    _start_login(client, "peer@example.com", "wrong-password", ip_address="10.0.0.41")
    _start_login(client, "peer@example.com", "wrong-password", ip_address="10.0.0.41")

    assign = client.post(
        "/api/rbac/assign-role",
        json={"email": "peer@example.com", "role": "admin"},
        headers=_auth_header(lead_token),
    )
    assert assign.status_code == 200

    dashboard = client.get("/api/admin/dashboard", headers=_auth_header(lead_token))
    assert dashboard.status_code == 200
    dashboard_json = dashboard.get_json()
    assert dashboard_json["system_summary"]["security_event_count"] >= 4
    assert dashboard_json["system_summary"]["audit_log_count"] >= 4
    assert len(dashboard_json["recent_audit_logs"]) >= 1
    assert dashboard_json["data_governance"]["pii_mode"] == "masked"

    risk_summary = client.get("/api/admin/risk-summary", headers=_auth_header(lead_token))
    assert risk_summary.status_code == 200
    users = risk_summary.get_json()["risk_summary"]["users"]
    assert any("***" in user["email"] for user in users)

    audit_logs = client.get("/api/admin/audit-logs", headers=_auth_header(lead_token))
    assert audit_logs.status_code == 200
    actions = {log["action"] for log in audit_logs.get_json()["logs"]}
    assert "login" in actions
    assert "assign_role" in actions


def test_health_endpoint_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_me_endpoint_returns_roles_and_permissions(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    token = _login(client, "lead@example.com", "Pass1234!").get_json()["access_token"]

    response = client.get("/api/auth/me", headers=_auth_header(token))
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["email"] == "lead@example.com"
    assert "admin" in payload["roles"]
    assert "admin:read" in payload["permissions"]
    assert "rbac:assign_role" in payload["permissions"]


def test_non_admin_is_denied_from_all_admin_endpoints(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")
    peer_token = _login(client, "peer@example.com", "Pass1234!").get_json()["access_token"]
    headers = _auth_header(peer_token)

    assert client.get("/api/admin/dashboard", headers=headers).status_code == 403
    assert client.get("/api/admin/security-events", headers=headers).status_code == 403
    assert client.get("/api/admin/audit-logs", headers=headers).status_code == 403
    assert client.get("/api/admin/risk-summary", headers=headers).status_code == 403


def test_assign_role_validation_errors(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    token = _login(client, "lead@example.com", "Pass1234!").get_json()["access_token"]
    headers = _auth_header(token)

    missing = client.post("/api/rbac/assign-role", json={"email": "peer@example.com"}, headers=headers)
    assert missing.status_code == 400

    unknown_user = client.post(
        "/api/rbac/assign-role",
        json={"email": "missing@example.com", "role": "admin"},
        headers=headers,
    )
    assert unknown_user.status_code == 404

    unknown_role = client.post(
        "/api/rbac/assign-role",
        json={"email": "lead@example.com", "role": "ghost-role"},
        headers=headers,
    )
    assert unknown_role.status_code == 404


def test_dashboard_limits_recent_event_and_audit_lists(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")
    token = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.50").get_json()["access_token"]

    for index in range(6):
        _start_login(client, "peer@example.com", "wrong-password", ip_address=f"10.0.1.{index}")

    dashboard = client.get("/api/admin/dashboard", headers=_auth_header(token))
    assert dashboard.status_code == 200
    payload = dashboard.get_json()
    assert len(payload["recent_security_events"]) <= 5
    assert len(payload["recent_audit_logs"]) <= 5


def test_login_requires_email_and_password(client):
    response = client.post("/api/auth/login", json={"email": ""})
    assert response.status_code == 400
    assert response.get_json()["error"] == "email and password are required"


def test_register_requires_all_fields(client):
    response = client.post("/api/auth/register", json={"username": "lead", "email": ""})
    assert response.status_code == 400
    assert response.get_json()["error"] == "username, email, and password are required"


def test_risk_summary_includes_risk_levels_and_system_counts(client):
    _register(client, "lead", "lead@example.com", "Pass1234")
    lead_token = _login(client, "lead@example.com", "Pass1234").get_json()["access_token"]
    _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.91")

    response = client.get("/api/admin/risk-summary", headers=_auth_header(lead_token))
    assert response.status_code == 200
    payload = response.get_json()
    assert "security_event_count" in payload["system_summary"]
    for user in payload["risk_summary"]["users"]:
        assert user["risk_level"] in {"low", "medium", "high"}


def test_me_requires_bearer_token(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.get_json()["error"] == "Missing bearer token"


def test_register_rejects_duplicate_email_with_generic_error(client):
    first = _register(client, "lead", "lead@example.com", "Pass1234!")
    duplicate = _register(client, "lead-two", "lead@example.com", "Pass1234!")

    assert first.status_code == 201
    assert duplicate.status_code == 400
    assert duplicate.get_json()["error"] == "Unable to register account"


def test_security_event_feed_is_capped_at_admin_limit(client):
    _register(client, "lead", "lead@example.com", "Pass1234")
    _register(client, "peer", "peer@example.com", "Pass1234")
    token = _login_from_ip(client, "lead@example.com", "Pass1234", "10.0.0.60").get_json()["access_token"]

    for index in range(25):
        _start_login(client, "peer@example.com", "wrong-password", ip_address=f"10.0.2.{index}")

    response = client.get("/api/admin/security-events", headers=_auth_header(token))
    assert response.status_code == 200
    assert len(response.get_json()["events"]) <= 20
    assert all("***" in event["email"] for event in response.get_json()["events"])


def test_create_app_rejects_default_secret_outside_test_mode():
    with pytest.raises(RuntimeError):
        create_app({"SECRET_KEY": Config.SECRET_KEY})


def test_client_ip_ignores_forwarded_header_when_proxy_trust_is_disabled():
    RateLimiter.reset()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "TRUST_PROXY_HEADERS": False,
            "BOOTSTRAP_ADMIN_EMAIL": "lead@example.com",
            "MFA_ENABLED": True,
            "SHOW_DEMO_MFA_CODE": True,
        }
    )
    local_client = app.test_client()
    _register(local_client, "lead", "lead@example.com", "Pass1234")

    first = _login_from_ip(local_client, "lead@example.com", "Pass1234", "127.0.0.1")
    second = local_client.post(
        "/api/auth/login",
        json={"email": "lead@example.com", "password": "Pass1234"},
        headers={"X-Forwarded-For": "10.1.1.11"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.get_json()["risk_assessment"]["signals"]["ip_change_detected"] is False


def test_first_user_is_not_admin_without_explicit_bootstrap_email():
    RateLimiter.reset()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "BOOTSTRAP_ADMIN_EMAIL": "",
            "TRUST_PROXY_HEADERS": True,
            "MFA_ENABLED": True,
            "SHOW_DEMO_MFA_CODE": True,
        }
    )
    local_client = app.test_client()

    reg = _register(local_client, "lead", "lead@example.com", "Pass1234")
    assert reg.status_code == 201
    assert reg.get_json()["roles"] == ["user"]


def test_login_requires_valid_one_time_code(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    challenge = _start_login(client, "lead@example.com", "Pass1234!")
    payload = challenge.get_json()

    bad = _verify_code(client, payload["challenge_id"], "000000")
    assert bad.status_code == 401
    assert bad.get_json()["error"] == "Invalid verification code"



def test_admin_responses_mask_personal_data_by_default(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    token = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.70").get_json()["access_token"]
    _start_login(client, "lead@example.com", "wrong-password", ip_address="10.0.0.71")

    events = client.get("/api/admin/security-events", headers=_auth_header(token))
    assert events.status_code == 200
    payload = events.get_json()
    assert payload["data_governance"]["pii_mode"] == "masked"
    assert any("***" in event["email"] for event in payload["events"])
    assert any("***" in event["ip_address"] for event in payload["events"])


def test_console_login_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecureAccessAI Console" in response.data
    assert b'id="root"' in response.data
    assert b"console/app.js" in response.data


def test_demo_alias_redirects_to_login_page(client):
    response = client.get("/demo", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_demo_admin_seeded_account_can_complete_demo_login_flow():
    RateLimiter.reset()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "TRUST_PROXY_HEADERS": True,
            "MFA_ENABLED": True,
            "MFA_CODE_TTL_SECONDS": 300,
            "SHOW_DEMO_MFA_CODE": True,
            "DEMO_ADMIN_EMAIL": "demo-admin@example.com",
            "DEMO_ADMIN_PASSWORD": "Pass1234!",
            "DEMO_ADMIN_USERNAME": "demo-admin",
        }
    )
    local_client = app.test_client()

    page = local_client.get("/")
    assert page.status_code == 200
    assert b"window.SECUREACCESS_BOOTSTRAP" in page.data
    assert b"demo-admin@example.com" in page.data

    challenge = _start_login(local_client, "demo-admin@example.com", "Pass1234!", ip_address="10.0.3.10")
    assert challenge.status_code == 200
    payload = challenge.get_json()
    assert payload["mfa_required"] is True
    verify = _verify_code(local_client, payload["challenge_id"], payload["demo_code"], ip_address="10.0.3.10")
    assert verify.status_code == 200

    token = verify.get_json()["access_token"]
    me = local_client.get("/api/auth/me", headers=_auth_header(token))
    assert me.status_code == 200
    assert "admin" in me.get_json()["roles"]


def test_admin_can_list_and_delete_other_users(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")

    token = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.3.20").get_json()["access_token"]
    users_response = client.get("/api/admin/users", headers=_auth_header(token))
    assert users_response.status_code == 200
    users = users_response.get_json()["users"]
    peer = next(user for user in users if user["username"] == "peer")
    assert peer["masked_email"].startswith("p***@")

    delete_response = client.delete(f"/api/admin/users/{peer['id']}", headers=_auth_header(token))
    assert delete_response.status_code == 200
    assert delete_response.get_json()["deleted_user"]["id"] == peer["id"]

    after = client.get("/api/admin/users", headers=_auth_header(token))
    assert all(user["username"] != "peer" for user in after.get_json()["users"])

    self_delete = client.delete("/api/admin/users/1", headers=_auth_header(token))
    assert self_delete.status_code == 400


def test_audit_logs_include_masked_ip_detail(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")

    token = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.3.30").get_json()["access_token"]
    client.post(
        "/api/rbac/assign-role",
        json={"email": "peer@example.com", "role": "admin"},
        headers={**_auth_header(token), "X-Forwarded-For": "10.0.3.31"},
    )

    logs = client.get("/api/admin/audit-logs", headers=_auth_header(token))
    assert logs.status_code == 200
    details = [log["detail"] for log in logs.get_json()["logs"] if log.get("detail")]
    assert any("ip=" in detail for detail in details)
    assert any("***" in detail for detail in details)


def test_login_page_includes_console_bootstrap(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"window.SECUREACCESS_BOOTSTRAP" in response.data
    assert b"console/app.css" in response.data
    assert b"console/app.js" in response.data


def test_dashboard_page_renders_dashboard_mode(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"window.SECUREACCESS_BOOTSTRAP" in response.data
    assert b'pageMode: "dashboard"' in response.data
    assert b"console/app.js" in response.data
