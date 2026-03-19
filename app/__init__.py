from flask import Flask, jsonify

from app.config import Config
from app.extensions import db
from app.routes.admin import admin_bp
from app.routes.auth import auth_bp
from app.routes.rbac import rbac_bp
from app.services.authorization_service import seed_rbac


def _initialize_database(app: Flask) -> None:
    db.init_app(app)
    with app.app_context():
        db.create_all()
        seed_rbac()
        db.session.commit()


def _register_blueprints(app: Flask) -> None:
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(rbac_bp)


def _register_health_route(app: Flask) -> None:
    @app.get('/health')
    def health():
        return jsonify({'status': 'ok'})


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    _initialize_database(app)
    _register_blueprints(app)
    _register_health_route(app)
    return app
