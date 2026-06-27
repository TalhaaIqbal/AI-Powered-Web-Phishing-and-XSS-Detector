from typing import Generic, TypeVar
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import DeclarativeMeta
from ..core.database import Base

ModelType = TypeVar('ModelType', bound=Base)

class BaseRepository(Generic[ModelType]):
    model: type[ModelType]
    
    def __init__(self, db: Session):
        self._db = db
    
    def get_all(self):
        return self._db.query(self.model).all()
    
    def get_by_id(self, id: int):
        return self._db.query(self.model).filter(self.model.id == id).first()

    def create(self, obj):
        self._db.add(obj)
        self._db.commit()
        self._db.refresh(obj)
        return obj
    
    def update(self, obj):
        self._db.commit()
        self._db.refresh(obj)
        return obj
    
    def delete(self, obj):
        self._db.delete(obj)
        self._db.flush()