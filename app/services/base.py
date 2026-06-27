from typing import Generic, TypeVar
from sqlalchemy.orm import Session
from ..core.database import Base
from ..repositories.base import BaseRepository

ModelType = TypeVar("ModelType", bound=Base)
RepositoryType = TypeVar("RepositoryType", bound=BaseRepository)

class BaseService(Generic[ModelType, RepositoryType]):
    repository_class: type[RepositoryType]

    def __init__(self, db: Session) -> None:
        self._db = db
        self.repository = self.repository_class(db)
    
    def get_by_id(self, id: int):
        return self.repository.get_by_id(id)
    
    def get_all(self):
        return self.repository.get_all()
    
    def create(self, obj):
        return self.repository.create(obj)
    
    def update(self, obj):
        return self.repository.update(obj)
    
    def delete(self, obj):
        return self.repository.delete(obj)