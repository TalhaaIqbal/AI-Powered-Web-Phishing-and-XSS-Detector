from ..services.user_service import UserService
from fastapi import APIRouter, Depends, HTTPException
from ..core.database import get_db
from ..core.security import hash_password
from sqlalchemy.orm import Session
from ..schemas.user_schema import UserResponse, UserCreate, UserUpdate

router = APIRouter(prefix="/users", tags=["Users"])

def get_user_service(db: Session = Depends(get_db)):
    return UserService(db)

@router.get("/", response_model=list[UserResponse])
def get_users(service: UserService = Depends(get_user_service)):
    try:
        return service.get_all_users()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/", response_model=UserResponse)
def create_user(user_data: UserCreate, service: UserService = Depends(get_user_service)):
    try:
        hashed_password = hash_password(user_data.password)
        user = service.create_user(user_data, hashed_password)
        if not user:
            raise HTTPException(status_code=400, detail="User with this email already exists")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, service: UserService = Depends(get_user_service)):
    try:
        user = service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_data: UserUpdate, service: UserService = Depends(get_user_service)):
    try:
        user = service.update_user(user_id, user_data)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{user_id}")
def delete_user(user_id: int, service: UserService = Depends(get_user_service)):
    try:
        user = service.delete_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))