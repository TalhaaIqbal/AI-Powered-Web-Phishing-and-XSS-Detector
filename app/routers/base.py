from fastapi import APIRouter
from .user_router import router as user_router
from .auth_router import router as auth_router
from .prediction_router import router as prediction_router

router = APIRouter()

router.include_router(user_router)
router.include_router(auth_router)
router.include_router(prediction_router)