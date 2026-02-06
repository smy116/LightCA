from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.security import decode_access_token, verify_password, is_bcrypt_hash
from app.config import settings

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if payload is None:
        raise credentials_exception
    
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    
    return {"username": username}


async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """Get current active user"""
    return current_user


def verify_admin_password(username: str, password: str) -> bool:
    """Verify admin password"""
    if username != settings.ADMIN:
        return False
    
    if is_bcrypt_hash(settings.ADMIN_PASSWORD):
        return verify_password(password, settings.ADMIN_PASSWORD)
    else:
        return password == settings.ADMIN_PASSWORD
