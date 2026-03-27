from flask import Flask, jsonify
import pyotp

from app.config import Config
from app.extensions import db
from app.models import Role, TotpCredential, User
from app.routes.admin import admin_bp
from app.routes.auth import auth_bp
from app.routes.rbac import rbac_bp
from app.routes.ui import ui_bp
from app.services.authorization_service import seed_rbac

INSECURE_SECRET_KEYS = {"dev-secret-change-me", "change-this-in-production", "test-secret"}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    if not app.config.get("TESTING") and app.config.get("SECRET_KEY") in INSECURE_SECRET_KEYS:
        raise RuntimeError("Set a non-default SECRET_KEY before starting the application")

    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_rbac()
        _ensure_demo_admin(app)
        _ensure_demo_totp(app)
        db.session.commit()

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(rbac_bp)
    app.register_blueprint(ui_bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


def _ensure_demo_admin(app: Flask) -> None:
    email = app.config.get("DEMO_ADMIN_EMAIL", "").strip().lower()
    password = app.config.get("DEMO_ADMIN_PASSWORD", "").strip()
    username = app.config.get("DEMO_ADMIN_USERNAME", "demo-admin").strip() or "demo-admin"
    if not email or not password:
        return

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email, is_active=True)
        db.session.add(user)
    else:
        user.username = username
        user.is_active = True

    user.set_password(password)

    admin_role = Role.query.filter_by(name="admin").first()
    user_role = Role.query.filter_by(name="user").first()
    if admin_role and admin_role not in user.roles:
        user.roles.append(admin_role)
    if user_role and user_role not in user.roles:
        user.roles.append(user_role)


def _ensure_demo_totp(app: Flask) -> None:
    if not app.config.get("DEMO_TOTP_ENABLED", True):
        return

    email = app.config.get("DEMO_ADMIN_EMAIL", "").strip().lower()
    if not email:
        return

    user = User.query.filter_by(email=email).first()
    if not user:
        return

    issuer = app.config.get("DEMO_TOTP_ISSUER", "SecureAccessAI").strip() or "SecureAccessAI"
    label = email
    credential = TotpCredential.query.filter_by(user_id=user.id).first()
    if not credential:
        credential = TotpCredential(
            user_id=user.id,
            issuer=issuer,
            label=label,
            secret=pyotp.random_base32(),
        )
        db.session.add(credential)
        return

    credential.issuer = issuer
    credential.label = label
