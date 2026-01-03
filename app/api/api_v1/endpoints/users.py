from typing import Any
from fastapi import APIRouter, HTTPException
from sqlmodel import select

from app.api import deps
from app.core import security
from app.models.user import User, UserCreate, UserPublic

router = APIRouter()

@router.post("/", response_model=UserPublic)
def create_user(
    *,
    session: deps.SessionDep,
    user_in: UserCreate,
) -> Any:
    """
    Create new user.
    """
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system",
        )
    
    user = User.model_validate(user_in, update={"hashed_password": security.get_password_hash(user_in.password)})
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
