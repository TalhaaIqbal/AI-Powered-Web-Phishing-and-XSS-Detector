from ..repositories.user_repository import UserRepository
from ..models.user import User
from sqlalchemy.orm import Session
from ..core.security import verify_password, hash_password

class AuthService:
    def __init__(self, db: Session) -> None:
        self.repository = UserRepository(db)

    def authenticate(self, email: str, password: str):
        user = self.repository.get_by_email(email)

        if not user:
            return None
        if not verify_password(password, user.password):
            return None
        return user

    def register(self, email: str, password: str, first_name: str, last_name: str, phone: str):
        existing_user = self.repository.get_by_email(email)
        if existing_user:
            return None

        hashed_password = hash_password(password)
        user = User(
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            phone=phone
        )
        return self.repository.create(user)