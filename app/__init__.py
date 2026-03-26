from flask import Flask, jsonify

from app.config import Config
from app.extensions import db
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
        db.session.commit()

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(rbac_bp)
    app.register_blueprint(ui_bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app
