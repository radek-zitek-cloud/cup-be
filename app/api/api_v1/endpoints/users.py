from typing import Any
from fastapi import APIRouter, HTTPException, Request
from sqlmodel import select

from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.ratelimit import limiter
from app.models.user import (
    User,
    UserCreate,
    UserPublic,
    UpdatePassword,
    UserUpdateMe,
    UserCreateAdmin,
)

router = APIRouter()


@router.post("/signup", response_model=UserPublic)
@limiter.limit(settings.RATE_LIMIT_SIGNUP)
def signup(
    *,
    request: Request,
    session: deps.SessionDep,
    user_in: UserCreate,
) -> Any:
    """
    Register a new user.
    """
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system",
        )

    user = User.model_validate(
        user_in,
        update={"hashed_password": security.get_password_hash(user_in.password)},
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post("/", response_model=UserPublic)
@limiter.limit("10/minute")
def create_user(
    *,
    request: Request,
    session: deps.SessionDep,
    user_in: UserCreateAdmin,
    current_user: deps.CurrentSuperUser,
) -> Any:
    """
    Create new user (admin only).
    Requires superuser permissions.
    """
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system",
        )

    user = User.model_validate(
        user_in,
        update={"hashed_password": security.get_password_hash(user_in.password)},
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.get("/me", response_model=UserPublic)
def read_user_me(current_user: deps.CurrentUser) -> Any:
    """
    Get current user.
    """
    return current_user


@router.patch("/me", response_model=UserPublic)
def update_user_me(
    *, session: deps.SessionDep, user_in: UserUpdateMe, current_user: deps.CurrentUser
) -> Any:
    """
    Update own user profile.
    """
    if user_in.email:
        existing_user = session.exec(
            select(User).where(User.email == user_in.email)
        ).first()
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(
                status_code=400, detail="User with this email already exists"
            )

    user_data = user_in.model_dump(exclude_unset=True)
    current_user.sqlmodel_update(user_data)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user


@router.patch("/me/password")
def update_password_me(
    *, session: deps.SessionDep, body: UpdatePassword, current_user: deps.CurrentUser
) -> Any:
    """
    Update own password.
    """
    if not security.verify_password(
        body.current_password, current_user.hashed_password
    ):
        raise HTTPException(status_code=400, detail="Incorrect password")
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as the current one"
        )

    hashed_password = security.get_password_hash(body.new_password)
    current_user.hashed_password = hashed_password
    session.add(current_user)
    session.commit()
    return {"message": "Password updated successfully"}
