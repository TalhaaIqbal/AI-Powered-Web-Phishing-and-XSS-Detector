import utils.session
from .core.database import Base, engine
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers.base import router as base_router
from .core.config import settings
from .core.security_middleware import get_security_middleware

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CyberGuard API",
    description="Cybersecurity threat detection and response platform",
    version="1.0.0",
    middleware=get_security_middleware()
)

# CORS Middleware - Restrict to specific origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Add your frontend URLs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(base_router)

@app.get("/")
def root():
    return {"message": "Welcome to CyberGuard API"}