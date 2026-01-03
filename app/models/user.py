from typing import Optional
from sqlmodel import Field, SQLModel
from pydantic import EmailStr

# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True)
    is_active: bool = True
    is_super: bool = False
    full_name: str | None = None

# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str

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
    new_password: str

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
