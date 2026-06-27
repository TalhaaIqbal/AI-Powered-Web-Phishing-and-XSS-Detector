from ..services.auth_service import AuthService
from fastapi import APIRouter, Depends, HTTPException
from ..core.database import get_db
from sqlalchemy.orm import Session
from ..schemas.auth_schema import authLogin, authRegister, Token
from ..schemas.user_schema import UserResponse
from ..core.security import create_access_token
from ..core.dependencies import get_current_user
from ..models.user import User

router = APIRouter(prefix="/auth", tags=["Auth"])

def get_auth_service(db: Session = Depends(get_db)):
    return AuthService(db)

@router.post("/login", response_model=Token)
def login(user_data: authLogin, service: AuthService = Depends(get_auth_service)):
    try:
        user = service.authenticate(user_data.email, user_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        access_token = create_access_token(data={"sub": str(user.id)})
        return Token(access_token=access_token)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/register", response_model=UserResponse)
def register(user_data: authRegister, service: AuthService = Depends(get_auth_service)):
    try:
        # Validate password confirmation
        if user_data.password != user_data.password_confirm:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        user = service.register(user_data.email, user_data.password, user_data.first_name, user_data.last_name, user_data.phone)
        if not user:
            raise HTTPException(status_code=400, detail="User with this email already exists")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user
