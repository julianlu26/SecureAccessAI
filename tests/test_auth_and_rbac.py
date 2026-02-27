import pytest

from app import create_app


@pytest.fixture()
def client():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret",
            "JWT_EXPIRES_MINUTES": 30,
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


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_sp1_register_and_login(client):
    reg = _register(client, "lead", "lead@example.com", "Pass1234!")
    assert reg.status_code == 201
    assert "admin" in reg.get_json()["roles"]

    login = _login(client, "lead@example.com", "Pass1234!")
    assert login.status_code == 200
    assert "access_token" in login.get_json()


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
