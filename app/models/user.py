from datetime import datetime
from pydantic import EmailStr, field_validator
from sqlmodel import Field, SQLModel
from app.core.security import validate_password_strength


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True)
    is_active: bool = True
    is_super: bool = False
    full_name: str | None = None


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=100)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password complexity."""
        return validate_password_strength(v)


class UserCreateAdmin(UserCreate):
    """Admin-only user creation with all privileges."""

    is_super: bool = False
    is_active: bool = True


# Properties to receive via API on update
class UserUpdate(SQLModel):
    email: EmailStr | None = None
    full_name: str | None = None
    is_super: bool | None = None


class UserUpdateMe(SQLModel):
    email: EmailStr | None = None
    full_name: str | None = None


class UpdatePassword(SQLModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=100)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        """Validate new password complexity."""
        return validate_password_strength(v)


# Properties to return via API
class UserPublic(UserBase):
    id: int


# Database model
class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str


# Token
class Token(SQLModel):
    access_token: str
    token_type: str
    refresh_token: str


class TokenData(SQLModel):
    sub: str | None = None


class TokenBlacklist(SQLModel, table=True):
    token: str = Field(primary_key=True, index=True)
    expires_at: datetime
