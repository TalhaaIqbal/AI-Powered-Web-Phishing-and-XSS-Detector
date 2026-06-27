from sqlalchemy.orm import Session
from .base import BaseRepository
from ..models.user import User

class UserRepository(BaseRepository[User]):
    model = User

    def __init__(self, db: Session):
        super().__init__(db)
    
    def get_by_email(self, email: str):
        return self._db.query(self.model).filter(self.model.email == email).first()