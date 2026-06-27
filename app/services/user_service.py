from ..repositories.user_repository import UserRepository
from ..schemas.user_schema import UserCreate, UserUpdate
from sqlalchemy.orm import Session
from ..models.user import User
from ..core.security import hash_password

class UserService:
    def __init__(self, db: Session) -> None:
        self.repository = UserRepository(db)

    def get_all_users(self):
        return self.repository.get_all()

    def get_user_by_id(self, user_id: int):
        return self.repository.get_by_id(user_id)

    def create_user(self, user_data: UserCreate, hashed_password: str):
        user = self.repository.get_by_email(user_data.email)
        if user:
            return None

        user = User(
            email = user_data.email,
            password = hashed_password,
            first_name = user_data.first_name,
            last_name = user_data.last_name,
            phone = user_data.phone
        )

        return self.repository.create(user)

    def update_user(self, user_id: int, user_data: UserUpdate):
        user = self.repository.get_by_id(user_id)
        if not user:
            return None

        if user_data.email is not None:
            user.email = user_data.email
        if user_data.password is not None:
            user.password = hash_password(user_data.password)

        return self.repository.update(user)

    def get_user_by_email(self, email: str):
        return self.repository.get_by_email(email)

    def delete_user(self, user_id: int):
        user = self.repository.get_by_id(user_id)
        if not user:
            return None
        return self.repository.delete(user)