from app.extensions import db
from app.models import User


class UserRepository:
    def get_by_email(self, email: str) -> User | None:
        return User.query.filter_by(email=email).first()

    def get_by_id(self, user_id: int) -> User | None:
        return db.session.get(User, user_id)

    def create(self, username: str, email: str, password: str) -> User:
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        return user
