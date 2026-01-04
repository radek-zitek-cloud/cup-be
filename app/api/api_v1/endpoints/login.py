from datetime import timedelta, datetime, timezone
from typing import Annotated, Any
from fastapi import APIRouter, Depends, HTTPException, Body, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select
from jose import jwt, JWTError
from pydantic import ValidationError

from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.ratelimit import limiter
from app.models.user import Token, User, TokenData, TokenBlacklist

router = APIRouter()


@router.post("/login/access-token", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login_access_token(
    request: Request,
    session: deps.SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = session.exec(select(User).where(User.email == form_data.username)).first()

    if not user or not security.verify_password(
        form_data.password, user.hashed_password
    ):
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
@limiter.limit("10/minute")
def refresh_token(
    request: Request,
    session: deps.SessionDep,
    refresh_token: Annotated[str, Body(embed=True)],
) -> Any:
    """
    Refresh access token
    """
    # Check if refresh token is blacklisted
    blacklisted = session.exec(
        select(TokenBlacklist).where(TokenBlacklist.token == refresh_token)
    ).first()
    if blacklisted:
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
        )

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
def logout(
    session: deps.SessionDep,
    token: deps.TokenDep,
    refresh_token: Annotated[str | None, Body(embed=True)] = None,
) -> Any:
    """
    Log out and invalidate tokens.
    """
    # Blacklist access token
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        exp = payload.get("exp")
        if exp:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            session.add(TokenBlacklist(token=token, expires_at=expires_at))
    except (JWTError, ValidationError):
        pass  # Token already invalid or expired

    # Blacklist refresh token if provided
    if refresh_token:
        try:
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            exp = payload.get("exp")
            if exp:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                session.add(TokenBlacklist(token=refresh_token, expires_at=expires_at))
        except (JWTError, ValidationError):
            pass

    session.commit()
    return {"message": "Successfully logged out"}
