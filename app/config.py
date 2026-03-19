import os


class Config:
    TESTING = os.getenv('TESTING', 'false').lower() == 'true'
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-me')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///secureaccessai.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRES_MINUTES = int(os.getenv('JWT_EXPIRES_MINUTES', '60'))
    LOGIN_RATE_LIMIT_COUNT = int(os.getenv('LOGIN_RATE_LIMIT_COUNT', '5'))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('LOGIN_RATE_LIMIT_WINDOW_SECONDS', '60'))
    LOGIN_FAILURE_THRESHOLD = int(os.getenv('LOGIN_FAILURE_THRESHOLD', '3'))
    LOGIN_FAILURE_WINDOW_MINUTES = int(os.getenv('LOGIN_FAILURE_WINDOW_MINUTES', '15'))
    RISK_IP_LOOKBACK_HOURS = int(os.getenv('RISK_IP_LOOKBACK_HOURS', '24'))

    SECURITY_TUNABLE_KEYS = (
        'JWT_EXPIRES_MINUTES',
        'LOGIN_RATE_LIMIT_COUNT',
        'LOGIN_RATE_LIMIT_WINDOW_SECONDS',
        'LOGIN_FAILURE_THRESHOLD',
        'LOGIN_FAILURE_WINDOW_MINUTES',
        'RISK_IP_LOOKBACK_HOURS',
    )

    @classmethod
    def security_runtime_defaults(cls) -> dict:
        return {key: getattr(cls, key) for key in cls.SECURITY_TUNABLE_KEYS}
