from datetime import timedelta
from typing import Annotated, Any
from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select
from jose import jwt, JWTError
from pydantic import ValidationError

from app.api import deps
from app.core import security
from app.core.config import settings
from app.models.user import Token, User, TokenData

router = APIRouter()

@router.post("/login/access-token", response_model=Token)
def login_access_token(
    session: deps.SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = session.exec(
        select(User).where(User.email == form_data.username)
    ).first()
    
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    return Token(
        access_token=security.create_access_token(
            user.email, expires_delta=access_token_expires
        ),
        refresh_token=security.create_access_token(
            user.email, expires_delta=refresh_token_expires
        ),
        token_type="bearer",
    )

@router.post("/login/refresh", response_model=Token)
def refresh_token(
    session: deps.SessionDep, refresh_token: Annotated[str, Body(embed=True)]
) -> Any:
    """
    Refresh access token
    """
    try:
        payload = jwt.decode(
            refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenData(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=403,
            detail="Could not validate credentials",
        )
    user = session.exec(select(User).where(User.email == token_data.sub)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    return Token(
        access_token=security.create_access_token(
            user.email, expires_delta=access_token_expires
        ),
        refresh_token=security.create_access_token(
            user.email, expires_delta=refresh_token_expires
        ),
        token_type="bearer",
    )

@router.post("/login/logout")
def logout() -> Any:
    """
    Log out (client should also delete the token)
    """
    return {"message": "Successfully logged out"}
