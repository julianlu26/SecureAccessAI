import pytest

from app import create_app
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
        }
    )
    return app.test_client()


def _register(client, username, email, password):
    return client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )


def _login(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def _login_from_ip(client, email, password, ip_address):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip_address},
    )


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_sp1_register_and_login(client):
    reg = _register(client, "lead", "lead@example.com", "Pass1234!")
    assert reg.status_code == 201
    assert "admin" in reg.get_json()["roles"]

    login = _login(client, "lead@example.com", "Pass1234!")
    assert login.status_code == 200
    assert "access_token" in login.get_json()
    assert login.get_json()["risk_assessment"]["score"] == 0


def test_sp2_rbac_endpoint_restriction_and_role_assignment(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")
    _register(client, "peer", "peer@example.com", "Pass1234!")

    lead_token = _login(client, "lead@example.com", "Pass1234!").get_json()["access_token"]
    peer_token = _login(client, "peer@example.com", "Pass1234!").get_json()["access_token"]

    # Peer cannot access admin dashboard before role assignment.
    denied = client.get("/api/admin/dashboard", headers=_auth_header(peer_token))
    assert denied.status_code == 403

    # Lead assigns admin role to peer.
    assign = client.post(
        "/api/rbac/assign-role",
        json={"email": "peer@example.com", "role": "admin"},
        headers=_auth_header(lead_token),
    )
    assert assign.status_code == 200

    # Peer can now access protected endpoint.
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

    first = _login_from_ip(client, "lead@example.com", "wrong-password", "10.0.0.10")
    second = _login_from_ip(client, "lead@example.com", "wrong-password", "10.0.0.10")
    third = _login_from_ip(client, "lead@example.com", "wrong-password", "10.0.0.10")

    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 403
    assert third.get_json()["risk_assessment"]["score"] >= 35
    assert third.get_json()["risk_assessment"]["signals"]["failed_attempt_burst"] is True


def test_sp3_rate_limiter_returns_429(client):
    _register(client, "lead", "lead@example.com", "Pass1234!")

    for _ in range(5):
        response = _login_from_ip(client, "lead@example.com", "wrong-password", "10.0.0.20")
        assert response.status_code in (401, 403)

    blocked = _login_from_ip(client, "lead@example.com", "Pass1234!", "10.0.0.20")
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

    _login_from_ip(client, "peer@example.com", "wrong-password", "10.0.0.41")
    _login_from_ip(client, "peer@example.com", "wrong-password", "10.0.0.41")
    _login_from_ip(client, "peer@example.com", "wrong-password", "10.0.0.41")

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

    risk_summary = client.get("/api/admin/risk-summary", headers=_auth_header(lead_token))
    assert risk_summary.status_code == 200
    users = risk_summary.get_json()["risk_summary"]["users"]
    assert any(user["email"] == "peer@example.com" for user in users)

    audit_logs = client.get("/api/admin/audit-logs", headers=_auth_header(lead_token))
    assert audit_logs.status_code == 200
    actions = {log["action"] for log in audit_logs.get_json()["logs"]}
    assert "login" in actions
    assert "assign_role" in actions

def test_health_endpoint_returns_ok(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}

def test_me_endpoint_returns_roles_and_permissions(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234!')
    token = _login(client, 'lead@example.com', 'Pass1234!').get_json()['access_token']

    response = client.get('/api/auth/me', headers=_auth_header(token))
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['email'] == 'lead@example.com'
    assert 'admin' in payload['roles']
    assert 'admin:read' in payload['permissions']
    assert 'rbac:assign_role' in payload['permissions']

def test_non_admin_is_denied_from_all_admin_endpoints(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234!')
    _register(client, 'peer', 'peer@example.com', 'Pass1234!')
    peer_token = _login(client, 'peer@example.com', 'Pass1234!').get_json()['access_token']
    headers = _auth_header(peer_token)

    assert client.get('/api/admin/dashboard', headers=headers).status_code == 403
    assert client.get('/api/admin/security-events', headers=headers).status_code == 403
    assert client.get('/api/admin/audit-logs', headers=headers).status_code == 403
    assert client.get('/api/admin/risk-summary', headers=headers).status_code == 403

def test_assign_role_validation_errors(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234!')
    token = _login(client, 'lead@example.com', 'Pass1234!').get_json()['access_token']
    headers = _auth_header(token)

    missing = client.post('/api/rbac/assign-role', json={'email': 'peer@example.com'}, headers=headers)
    assert missing.status_code == 400

    unknown_user = client.post(
        '/api/rbac/assign-role',
        json={'email': 'missing@example.com', 'role': 'admin'},
        headers=headers,
    )
    assert unknown_user.status_code == 404

    unknown_role = client.post(
        '/api/rbac/assign-role',
        json={'email': 'lead@example.com', 'role': 'ghost-role'},
        headers=headers,
    )
    assert unknown_role.status_code == 404

def test_dashboard_limits_recent_event_and_audit_lists(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234!')
    _register(client, 'peer', 'peer@example.com', 'Pass1234!')
    token = _login_from_ip(client, 'lead@example.com', 'Pass1234!', '10.0.0.50').get_json()['access_token']

    for index in range(6):
        _login_from_ip(client, 'peer@example.com', 'wrong-password', f'10.0.1.{index}')

    dashboard = client.get('/api/admin/dashboard', headers=_auth_header(token))
    assert dashboard.status_code == 200
    payload = dashboard.get_json()
    assert len(payload['recent_security_events']) <= 5
    assert len(payload['recent_audit_logs']) <= 5

def test_login_requires_email_and_password(client):
    response = client.post("/api/auth/login", json={"email": ""})
    assert response.status_code == 400
    assert response.get_json()["error"] == "email and password are required"


def test_register_requires_all_fields(client):
    response = client.post('/api/auth/register', json={'username': 'lead', 'email': ''})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'username, email, and password are required'


def test_risk_summary_includes_risk_levels_and_system_counts(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234')
    lead_token = _login(client, 'lead@example.com', 'Pass1234').get_json()['access_token']
    _login_from_ip(client, 'lead@example.com', 'wrong-password', '10.0.0.91')

    response = client.get('/api/admin/risk-summary', headers=_auth_header(lead_token))
    assert response.status_code == 200
    payload = response.get_json()
    assert 'security_event_count' in payload['system_summary']
    for user in payload['risk_summary']['users']:
        assert user['risk_level'] in {'low', 'medium', 'high'}


def test_event_and_audit_feeds_return_expected_keys(client):
    _register(client, 'lead', 'lead@example.com', 'Pass1234')
    token = _login(client, 'lead@example.com', 'Pass1234').get_json()['access_token']
    _login_from_ip(client, 'lead@example.com', 'wrong-password', '10.0.0.92')

    events = client.get('/api/admin/security-events', headers=_auth_header(token)).get_json()['events']
    logs = client.get('/api/admin/audit-logs', headers=_auth_header(token)).get_json()['logs']
    assert {'id', 'email', 'ip_address', 'event_type', 'outcome', 'risk_score', 'detail', 'created_at'} <= set(events[0].keys())
    assert {'id', 'actor_user_id', 'action', 'target_email', 'status', 'detail', 'created_at'} <= set(logs[0].keys())
