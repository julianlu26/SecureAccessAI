from flask import Blueprint, current_app, render_template

ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/")
def index():
    return render_template("demo.html", **_demo_context())


@ui_bp.get("/demo")
def demo():
    return render_template("demo.html", **_demo_context())


def _demo_context() -> dict:
    return {
        "demo_admin_email": current_app.config.get("DEMO_ADMIN_EMAIL", ""),
        "demo_admin_password": current_app.config.get("DEMO_ADMIN_PASSWORD", ""),
        "demo_admin_username": current_app.config.get("DEMO_ADMIN_USERNAME", "demo-admin"),
    }
