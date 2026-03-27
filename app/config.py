import os


class Config:
    TESTING = os.getenv("TESTING", "false").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secureaccessai.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
    LOGIN_RATE_LIMIT_COUNT = int(os.getenv("LOGIN_RATE_LIMIT_COUNT", "5"))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60"))
    LOGIN_FAILURE_THRESHOLD = int(os.getenv("LOGIN_FAILURE_THRESHOLD", "3"))
    LOGIN_FAILURE_WINDOW_MINUTES = int(os.getenv("LOGIN_FAILURE_WINDOW_MINUTES", "15"))
    RISK_IP_LOOKBACK_HOURS = int(os.getenv("RISK_IP_LOOKBACK_HOURS", "24"))
    TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
    BOOTSTRAP_ADMIN_EMAIL = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    DEMO_ADMIN_EMAIL = os.getenv("DEMO_ADMIN_EMAIL", "").strip().lower()
    DEMO_ADMIN_PASSWORD = os.getenv("DEMO_ADMIN_PASSWORD", "").strip()
    DEMO_ADMIN_USERNAME = os.getenv("DEMO_ADMIN_USERNAME", "demo-admin").strip() or "demo-admin"
    DEMO_TOTP_ENABLED = os.getenv("DEMO_TOTP_ENABLED", "true").lower() == "true"
    SHOW_DEMO_TOTP_QR = os.getenv("SHOW_DEMO_TOTP_QR", "true").lower() == "true"
    DEMO_TOTP_ISSUER = os.getenv("DEMO_TOTP_ISSUER", "SecureAccessAI").strip() or "SecureAccessAI"
    MFA_ENABLED = os.getenv("MFA_ENABLED", "true").lower() == "true"
    MFA_CODE_TTL_SECONDS = int(os.getenv("MFA_CODE_TTL_SECONDS", "300"))
    MFA_REQUIRE_SAME_IP = os.getenv("MFA_REQUIRE_SAME_IP", "true").lower() == "true"
    SHOW_DEMO_MFA_CODE = os.getenv("SHOW_DEMO_MFA_CODE", "false").lower() == "true"
    ADMIN_SHOW_FULL_PII = os.getenv("ADMIN_SHOW_FULL_PII", "false").lower() == "true"

    SECURITY_TUNABLE_KEYS = (
        "JWT_EXPIRES_MINUTES",
        "LOGIN_RATE_LIMIT_COUNT",
        "LOGIN_RATE_LIMIT_WINDOW_SECONDS",
        "LOGIN_FAILURE_THRESHOLD",
        "LOGIN_FAILURE_WINDOW_MINUTES",
        "RISK_IP_LOOKBACK_HOURS",
        "TRUST_PROXY_HEADERS",
        "DEMO_TOTP_ENABLED",
        "SHOW_DEMO_TOTP_QR",
        "DEMO_TOTP_ISSUER",
        "MFA_ENABLED",
        "MFA_CODE_TTL_SECONDS",
        "MFA_REQUIRE_SAME_IP",
        "SHOW_DEMO_MFA_CODE",
        "ADMIN_SHOW_FULL_PII",
    )

    @classmethod
    def security_runtime_defaults(cls) -> dict:
        return {key: getattr(cls, key) for key in cls.SECURITY_TUNABLE_KEYS}
