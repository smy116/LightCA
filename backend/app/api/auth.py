from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.auth import verify_admin_password
from app.schemas.auth import LoginRequest, LoginResponse
from app.schemas.common import success_response, error_response
from app.security import create_access_token
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Admin login",
    description="Authenticate the admin account and return a JWT access token.",
)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    if not verify_admin_password(request.username, request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(data={"sub": request.username})

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    )

    return {
        "token": token,
        "expires_at": expires_at.isoformat(),
    }
