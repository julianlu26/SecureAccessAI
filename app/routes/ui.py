import base64
from io import BytesIO

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from flask import Blueprint, current_app, redirect, render_template

from app.models import TotpCredential, User

ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/")
def index():
    return render_template("console.html", **_console_context(page_mode="login"))


@ui_bp.get("/demo")
def demo_redirect():
    return redirect("/")


@ui_bp.get("/dashboard")
def dashboard():
    return render_template("console.html", **_console_context(page_mode="dashboard"))


def _console_context(*, page_mode: str) -> dict:
    totp_context = _demo_totp_context()
    return {
        "page_mode": page_mode,
        "demo_admin_email": current_app.config.get("DEMO_ADMIN_EMAIL", ""),
        "demo_admin_password": current_app.config.get("DEMO_ADMIN_PASSWORD", ""),
        "demo_admin_username": current_app.config.get("DEMO_ADMIN_USERNAME", "demo-admin"),
        **totp_context,
    }


def _demo_totp_context() -> dict:
    if not current_app.config.get("DEMO_TOTP_ENABLED", True):
        return {
            "demo_totp_enabled": False,
            "demo_totp_qr_data_url": "",
            "demo_totp_secret": "",
            "demo_totp_issuer": "",
            "demo_totp_account": "",
        }

    email = current_app.config.get("DEMO_ADMIN_EMAIL", "").strip().lower()
    user = User.query.filter_by(email=email).first() if email else None
    credential = TotpCredential.query.filter_by(user_id=user.id).first() if user else None
    if not credential:
        return {
            "demo_totp_enabled": False,
            "demo_totp_qr_data_url": "",
            "demo_totp_secret": "",
            "demo_totp_issuer": "",
            "demo_totp_account": email,
        }

    qr_data_url = ""
    if current_app.config.get("SHOW_DEMO_TOTP_QR", True):
        otpauth_url = pyotp.TOTP(credential.secret).provisioning_uri(
            name=credential.label,
            issuer_name=credential.issuer,
        )
        buffer = BytesIO()
        qrcode.make(otpauth_url, image_factory=SvgPathImage).save(buffer)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        qr_data_url = f"data:image/svg+xml;base64,{encoded}"

    return {
        "demo_totp_enabled": True,
        "demo_totp_qr_data_url": qr_data_url,
        "demo_totp_secret": credential.secret,
        "demo_totp_issuer": credential.issuer,
        "demo_totp_account": credential.label,
    }
