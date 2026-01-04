import bcrypt
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Union
from jose import jwt
from fastapi import HTTPException, status
from app.core.config import settings


class PasswordRequirements:
    """Password complexity requirements from settings."""

    MIN_LENGTH = settings.PASSWORD_MIN_LENGTH
    MAX_LENGTH = 100
    REQUIRE_UPPERCASE = settings.PASSWORD_REQUIRE_UPPERCASE
    REQUIRE_LOWERCASE = settings.PASSWORD_REQUIRE_LOWERCASE
    REQUIRE_DIGIT = settings.PASSWORD_REQUIRE_DIGIT
    REQUIRE_SPECIAL = settings.PASSWORD_REQUIRE_SPECIAL


def validate_password_strength(password: str) -> str:
    """
    Validate password meets security requirements.
    """
    errors = []

    if len(password) < PasswordRequirements.MIN_LENGTH:
        errors.append(f"at least {PasswordRequirements.MIN_LENGTH} characters")

    if len(password) > PasswordRequirements.MAX_LENGTH:
        errors.append(f"no more than {PasswordRequirements.MAX_LENGTH} characters")

    if PasswordRequirements.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")

    if PasswordRequirements.REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")

    if PasswordRequirements.REQUIRE_DIGIT and not re.search(r"\d", password):
        errors.append("at least one digit")

    if PasswordRequirements.REQUIRE_SPECIAL and not re.search(
        r"[!@#$%^&*(),.?\":{}|<>]", password
    ):
        errors.append("at least one special character")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must contain {', '.join(errors)}",
        )

    return password


def create_access_token(
    subject: Union[str, Any], expires_delta: timedelta = None
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    """Hash password after validating strength."""
    validate_password_strength(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
