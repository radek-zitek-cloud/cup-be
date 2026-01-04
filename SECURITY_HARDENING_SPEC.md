# Backend Security Hardening Specification

**Project:** cup-be
**Version:** 0.2.1
**Date:** 2026-01-04
**Author:** Security Review Team

---

## Table of Contents

1. [Overview](#overview)
2. [Critical Issues (Priority 1)](#critical-issues-priority-1)
3. [High Priority Issues (Priority 2)](#high-priority-issues-priority-2)
4. [Medium Priority Issues (Priority 3)](#medium-priority-issues-priority-3)
5. [Low Priority Issues (Priority 4)](#low-priority-issues-priority-4)
6. [Testing Requirements](#testing-requirements)
7. [Deployment Checklist](#deployment-checklist)

---

## Overview

This document provides detailed specifications for implementing security hardening, functionality completeness, and code quality improvements for the cup-be FastAPI backend application.

### Technology Stack
- **Framework:** FastAPI 0.128.0
- **ORM:** SQLModel 0.0.31
- **Database:** PostgreSQL 18
- **Authentication:** JWT (python-jose)
- **Password Hashing:** bcrypt 4.1.0

### Implementation Guidelines
- Follow FastAPI best practices
- Maintain backward compatibility where possible
- Write tests for all new functionality
- Update documentation for API changes
- Use environment variables for configuration
- Follow existing code style and patterns

---

## Critical Issues (Priority 1)

### CRIT-01: Restrict CORS to Specific Origins

**Severity:** 🔴 CRITICAL
**File:** `app/main.py:25-31`
**Current State:** CORS allows all origins (`allow_origins=["*"]`)

#### Problem
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ Allows any origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This configuration allows any website to make authenticated requests to the API, enabling CSRF attacks and unauthorized access from malicious domains.

#### Solution Specification

1. **Add CORS configuration to settings** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
```

2. **Update `.env.example`**
```bash
# CORS - comma-separated list of allowed origins
BACKEND_CORS_ORIGINS=http://localhost:3000,http://localhost:8080
```

3. **Update CORS middleware** (`app/main.py`)
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
```

#### Acceptance Criteria
- [x] CORS origins read from environment variable
- [x] Default to localhost in development
- [x] Explicit methods and headers (no wildcards)
- [x] Documentation updated with CORS configuration
- [x] Test that unauthorized origins are rejected

#### Test Cases
```python
def test_cors_allowed_origin(client: TestClient):
    response = client.options(
        "/api/v1/users/me",
        headers={"Origin": "http://localhost:3000"}
    )
    assert "access-control-allow-origin" in response.headers

def test_cors_forbidden_origin(client: TestClient):
    response = client.options(
        "/api/v1/users/me",
        headers={"Origin": "http://evil.com"}
    )
    assert "access-control-allow-origin" not in response.headers
```

---

### CRIT-02: Add Authentication to POST /users/ Endpoint

**Severity:** 🔴 CRITICAL
**File:** `app/api/api_v1/endpoints/users.py:38-61`
**Current State:** Unprotected endpoint allows anyone to create users

#### Problem
```python
@router.post("/", response_model=UserPublic)
def create_user(
    *,
    session: deps.SessionDep,
    user_in: UserCreate,
) -> Any:
    """
    Create new user (admin or internal).
    """
    # No authentication check!
```

This endpoint can be abused to create unlimited accounts, spam the database, or create admin accounts if `is_super` field is exposed.

#### Solution Specification

1. **Create admin-only dependency** (`app/api/deps.py`)
```python
def get_current_super_user(current_user: CurrentUser) -> User:
    """
    Dependency to verify current user is a superuser.
    """
    if not current_user.is_super:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user

CurrentSuperUser = Annotated[User, Depends(get_current_super_user)]
```

2. **Update endpoint to require admin** (`app/api/api_v1/endpoints/users.py`)
```python
@router.post("/", response_model=UserPublic)
def create_user(
    *,
    session: deps.SessionDep,
    user_in: UserCreate,
    current_user: deps.CurrentSuperUser,  # Add admin requirement
) -> Any:
    """
    Create new user (admin only).
    Requires superuser permissions.
    """
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system",
        )

    user = User.model_validate(
        user_in,
        update={"hashed_password": security.get_password_hash(user_in.password)},
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
```

3. **Create dedicated admin user model** (`app/models/user.py`)
```python
class UserCreateAdmin(UserCreate):
    """Admin-only user creation with all privileges."""
    is_super: bool = False
    is_active: bool = True
```

4. **Update endpoint to use admin model**
```python
def create_user(
    *,
    session: deps.SessionDep,
    user_in: UserCreateAdmin,  # Changed from UserCreate
    current_user: deps.CurrentSuperUser,
) -> Any:
```

#### Acceptance Criteria
- [x] Endpoint requires authentication
- [x] Only superusers can create users
- [x] Returns 403 for non-admin users
- [x] Returns 401 for unauthenticated requests
- [x] Existing `/signup` endpoint still works publicly
- [x] Tests cover admin and non-admin scenarios

#### Test Cases
```python
def test_create_user_requires_auth(client: TestClient):
    response = client.post(
        "/api/v1/users/",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert response.status_code == 401

def test_create_user_requires_admin(client: TestClient, regular_user_token: str):
    response = client.post(
        "/api/v1/users/",
        headers={"Authorization": f"Bearer {regular_user_token}"},
        json={"email": "test@example.com", "password": "password123"},
    )
    assert response.status_code == 403
    assert "Not enough permissions" in response.json()["detail"]

def test_create_user_admin_success(client: TestClient, admin_token: str):
    response = client.post(
        "/api/v1/users/",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": "test@example.com", "password": "password123", "is_super": True},
    )
    assert response.status_code == 200
    assert response.json()["is_super"] is True
```

---

### CRIT-03: Implement Rate Limiting on Authentication Endpoints

**Severity:** 🔴 CRITICAL
**Files:** `app/api/api_v1/endpoints/login.py`, `app/main.py`
**Current State:** No rate limiting - vulnerable to brute force attacks

#### Problem
Attackers can make unlimited login attempts to brute force passwords or enumerate valid email addresses.

#### Solution Specification

1. **Install slowapi dependency** (`pyproject.toml`)
```toml
dependencies = [
    # ... existing dependencies ...
    "slowapi>=0.1.9",
]
```

2. **Create rate limiting middleware** (`app/core/ratelimit.py`)
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/minute"],
    storage_uri="memory://",  # Use Redis in production
)

async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Custom handler for rate limit exceeded errors."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests. Please try again later.",
            "retry_after": exc.retry_after,
        },
    )
```

3. **Add to main app** (`app/main.py`)
```python
from slowapi.errors import RateLimitExceeded
from app.core.ratelimit import limiter, rate_limit_handler

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
```

4. **Apply to login endpoint** (`app/api/api_v1/endpoints/login.py`)
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)

@router.post("/login/access-token", response_model=Token)
@limiter.limit("5/minute")  # Max 5 login attempts per minute
def login_access_token(
    request: Request,  # Required for rate limiting
    session: deps.SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests.
    Rate limited to 5 attempts per minute per IP address.
    """
    # ... existing code ...
```

5. **Add rate limiting configuration** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_SIGNUP: str = "3/hour"
    RATE_LIMIT_PASSWORD_RESET: str = "3/hour"
    REDIS_URL: str | None = None  # For production: redis://localhost:6379
```

6. **Update rate limiter for production** (`app/core/ratelimit.py`)
```python
from app.core.config import settings

storage_uri = settings.REDIS_URL or "memory://"

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/minute"],
    storage_uri=storage_uri,
)
```

#### Acceptance Criteria
- [x] Login endpoint limited to 5 attempts/minute per IP
- [x] Signup endpoint limited to 3 attempts/hour per IP
- [x] Returns 429 status code when rate limit exceeded
- [x] Includes retry-after header in response
- [x] Uses Redis for distributed rate limiting in production
- [x] Rate limits configurable via environment variables
- [x] Tests verify rate limiting works

#### Test Cases
```python
def test_login_rate_limit(client: TestClient):
    # Create user first
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )

    # Make 5 login attempts (should succeed or fail based on credentials)
    for i in range(5):
        client.post(
            "/api/v1/login/access-token",
            data={"username": "test@example.com", "password": "wrong"},
        )

    # 6th attempt should be rate limited
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    assert response.status_code == 429
    assert "too many requests" in response.json()["detail"].lower()
    assert "retry_after" in response.json()
```

---

### CRIT-04: Add Password Complexity Requirements

**Severity:** 🔴 CRITICAL
**File:** `app/models/user.py:15-16`
**Current State:** No password validation

#### Problem
Users can create accounts with weak passwords like "123" or "a", making accounts vulnerable to compromise.

#### Solution Specification

1. **Create password validator** (`app/core/security.py`)
```python
import re
from fastapi import HTTPException, status

class PasswordRequirements:
    """Password complexity requirements."""
    MIN_LENGTH = 8
    MAX_LENGTH = 100
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = False  # Set to True for stricter policy


def validate_password_strength(password: str) -> str:
    """
    Validate password meets security requirements.

    Args:
        password: Plain text password to validate

    Returns:
        The password if valid

    Raises:
        HTTPException: If password doesn't meet requirements
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

    if PasswordRequirements.REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("at least one special character")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must contain {', '.join(errors)}",
        )

    return password


def get_password_hash(password: str) -> str:
    """Hash password after validating strength."""
    validate_password_strength(password)  # Validate before hashing
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
```

2. **Add Pydantic validator** (`app/models/user.py`)
```python
from pydantic import field_validator
from app.core.security import validate_password_strength

class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=100)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password complexity."""
        return validate_password_strength(v)


class UpdatePassword(SQLModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=100)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        """Validate new password complexity."""
        return validate_password_strength(v)
```

3. **Add configuration** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = False
```

4. **Update PasswordRequirements to use settings**
```python
from app.core.config import settings

class PasswordRequirements:
    """Password complexity requirements from settings."""
    MIN_LENGTH = settings.PASSWORD_MIN_LENGTH
    MAX_LENGTH = 100
    REQUIRE_UPPERCASE = settings.PASSWORD_REQUIRE_UPPERCASE
    REQUIRE_LOWERCASE = settings.PASSWORD_REQUIRE_LOWERCASE
    REQUIRE_DIGIT = settings.PASSWORD_REQUIRE_DIGIT
    REQUIRE_SPECIAL = settings.PASSWORD_REQUIRE_SPECIAL
```

#### Acceptance Criteria
- [ ] Passwords must be 8-100 characters
- [ ] Must contain uppercase letter
- [ ] Must contain lowercase letter
- [ ] Must contain digit
- [ ] Clear error messages for each requirement
- [ ] Applies to signup, user creation, and password change
- [ ] Configuration via environment variables
- [ ] Tests for valid and invalid passwords

#### Test Cases
```python
def test_signup_weak_password(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "weak"},
    )
    assert response.status_code == 422
    assert "uppercase" in response.json()["detail"].lower()

def test_signup_strong_password(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPass123"},
    )
    assert response.status_code == 200

def test_password_too_short(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "Aa1"},
    )
    assert response.status_code == 422
    assert "8 characters" in response.json()["detail"]

def test_password_missing_digit(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPassword"},
    )
    assert response.status_code == 422
    assert "digit" in response.json()["detail"].lower()
```

---

## High Priority Issues (Priority 2)

### HIGH-01: Implement Token Blacklist Cleanup Job

**Severity:** 🟠 HIGH
**File:** New file needed
**Current State:** Blacklisted tokens accumulate indefinitely

#### Problem
The `token_blacklist` table grows indefinitely as expired tokens are never removed, leading to performance degradation and unnecessary storage usage.

#### Solution Specification

1. **Create cleanup utility** (`app/core/cleanup.py`)
```python
from datetime import datetime, timezone
from sqlmodel import Session, select, delete
from app.models.user import TokenBlacklist
from app.db.session import engine
import logging

logger = logging.getLogger(__name__)


def cleanup_expired_tokens() -> int:
    """
    Remove expired tokens from blacklist.

    Returns:
        Number of tokens deleted
    """
    with Session(engine) as session:
        # Delete tokens where expires_at is in the past
        statement = delete(TokenBlacklist).where(
            TokenBlacklist.expires_at < datetime.now(timezone.utc)
        )
        result = session.exec(statement)
        session.commit()

        deleted_count = result.rowcount
        logger.info(f"Cleaned up {deleted_count} expired tokens from blacklist")
        return deleted_count
```

2. **Create background task** (`app/core/tasks.py`)
```python
import asyncio
from datetime import timedelta
import logging
from app.core.cleanup import cleanup_expired_tokens

logger = logging.getLogger(__name__)


async def periodic_token_cleanup(interval_hours: int = 24):
    """
    Run token cleanup periodically.

    Args:
        interval_hours: Hours between cleanup runs
    """
    while True:
        try:
            deleted = cleanup_expired_tokens()
            logger.info(f"Token cleanup completed: {deleted} tokens removed")
        except Exception as e:
            logger.error(f"Token cleanup failed: {e}", exc_info=True)

        # Wait for next interval
        await asyncio.sleep(interval_hours * 3600)
```

3. **Add to application lifespan** (`app/main.py`)
```python
from contextlib import asynccontextmanager
import asyncio
from app.core.tasks import periodic_token_cleanup

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run migrations on startup
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")

    # Start background cleanup task
    cleanup_task = asyncio.create_task(periodic_token_cleanup(interval_hours=24))

    yield

    # Cancel background task on shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
```

4. **Add manual cleanup endpoint** (`app/api/api_v1/endpoints/login.py`)
```python
from app.core.cleanup import cleanup_expired_tokens

@router.post("/login/cleanup-tokens")
def cleanup_tokens(current_user: deps.CurrentSuperUser) -> dict[str, int]:
    """
    Manually trigger token cleanup (admin only).
    """
    deleted = cleanup_expired_tokens()
    return {"deleted_tokens": deleted}
```

5. **Add configuration** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Background Tasks
    TOKEN_CLEANUP_INTERVAL_HOURS: int = 24
```

#### Acceptance Criteria
- [ ] Expired tokens automatically deleted every 24 hours
- [ ] Background task starts with application
- [ ] Configurable cleanup interval
- [ ] Manual cleanup endpoint for admins
- [ ] Logging of cleanup operations
- [ ] Graceful shutdown of background task
- [ ] Tests for cleanup functionality

#### Test Cases
```python
def test_cleanup_expired_tokens(session: Session):
    from datetime import timedelta
    from app.models.user import TokenBlacklist
    from app.core.cleanup import cleanup_expired_tokens

    # Add expired token
    expired_token = TokenBlacklist(
        token="expired_token",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )
    session.add(expired_token)

    # Add valid token
    valid_token = TokenBlacklist(
        token="valid_token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    session.add(valid_token)
    session.commit()

    # Run cleanup
    deleted = cleanup_expired_tokens()

    # Verify only expired token was deleted
    assert deleted == 1
    assert session.get(TokenBlacklist, "expired_token") is None
    assert session.get(TokenBlacklist, "valid_token") is not None
```

---

### HIGH-02: Add Account Lockout After Failed Login Attempts

**Severity:** 🟠 HIGH
**Files:** `app/models/user.py`, `app/api/api_v1/endpoints/login.py`
**Current State:** Unlimited login attempts even with rate limiting

#### Problem
Even with rate limiting, attackers can slowly brute force passwords. Account lockout provides additional protection.

#### Solution Specification

1. **Update User model** (`app/models/user.py`)
```python
class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str

    # Account lockout fields
    failed_login_attempts: int = Field(default=0)
    locked_until: datetime | None = Field(default=None)
```

2. **Create migration**
```bash
make make-migration msg="add account lockout fields to user"
```

Migration content:
```python
def upgrade() -> None:
    op.add_column('user', sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('user', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

def downgrade() -> None:
    op.drop_column('user', 'locked_until')
    op.drop_column('user', 'failed_login_attempts')
```

3. **Create lockout utilities** (`app/core/security.py`)
```python
from datetime import datetime, timedelta, timezone
from sqlmodel import Session
from app.models.user import User

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


def is_account_locked(user: User) -> bool:
    """Check if account is currently locked."""
    if user.locked_until is None:
        return False
    return datetime.now(timezone.utc) < user.locked_until


def record_failed_login(session: Session, user: User) -> None:
    """Record failed login attempt and lock if threshold exceeded."""
    user.failed_login_attempts += 1

    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=LOCKOUT_DURATION_MINUTES
        )

    session.add(user)
    session.commit()


def reset_failed_attempts(session: Session, user: User) -> None:
    """Reset failed login attempts on successful login."""
    user.failed_login_attempts = 0
    user.locked_until = None
    session.add(user)
    session.commit()
```

4. **Update login endpoint** (`app/api/api_v1/endpoints/login.py`)
```python
from app.core.security import is_account_locked, record_failed_login, reset_failed_attempts

@router.post("/login/access-token", response_model=Token)
@limiter.limit("5/minute")
def login_access_token(
    request: Request,
    session: deps.SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests.
    Implements account lockout after 5 failed attempts.
    """
    user = session.exec(select(User).where(User.email == form_data.username)).first()

    # Check if user exists
    if not user:
        # Return generic error to prevent email enumeration
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    # Check if account is locked
    if is_account_locked(user):
        lockout_remaining = (user.locked_until - datetime.now(timezone.utc)).total_seconds() / 60
        raise HTTPException(
            status_code=423,  # Locked
            detail=f"Account locked due to too many failed login attempts. Try again in {int(lockout_remaining)} minutes.",
        )

    # Verify password
    if not security.verify_password(form_data.password, user.hashed_password):
        record_failed_login(session, user)

        remaining_attempts = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
        if remaining_attempts > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Incorrect email or password. {remaining_attempts} attempts remaining.",
            )
        else:
            raise HTTPException(
                status_code=423,
                detail=f"Account locked due to too many failed attempts. Locked for {LOCKOUT_DURATION_MINUTES} minutes.",
            )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Successful login - reset failed attempts
    reset_failed_attempts(session, user)

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
```

5. **Add unlock endpoint** (`app/api/api_v1/endpoints/users.py`)
```python
@router.post("/users/{user_id}/unlock")
def unlock_user_account(
    *,
    session: deps.SessionDep,
    user_id: int,
    current_user: deps.CurrentSuperUser,
) -> dict[str, str]:
    """
    Unlock a locked user account (admin only).
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.failed_login_attempts = 0
    user.locked_until = None
    session.add(user)
    session.commit()

    return {"message": f"Account for {user.email} has been unlocked"}
```

6. **Add configuration** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Account Lockout
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30
```

#### Acceptance Criteria
- [ ] Account locks after 5 failed login attempts
- [ ] Locked for 30 minutes (configurable)
- [ ] Clear error message showing lockout status
- [ ] Failed attempts reset on successful login
- [ ] Admin can manually unlock accounts
- [ ] Database fields added via migration
- [ ] Tests for lockout scenarios

#### Test Cases
```python
def test_account_lockout_after_failed_attempts(client: TestClient):
    # Create user
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPass123"},
    )

    # Make 5 failed attempts
    for i in range(5):
        response = client.post(
            "/api/v1/login/access-token",
            data={"username": "test@example.com", "password": "wrongpassword"},
        )
        if i < 4:
            assert response.status_code == 400
        else:
            assert response.status_code == 423  # Locked

    # Try with correct password - should still be locked
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "StrongPass123"},
    )
    assert response.status_code == 423
    assert "locked" in response.json()["detail"].lower()

def test_failed_attempts_reset_on_success(client: TestClient):
    # Create user
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPass123"},
    )

    # Make 3 failed attempts
    for i in range(3):
        client.post(
            "/api/v1/login/access-token",
            data={"username": "test@example.com", "password": "wrongpassword"},
        )

    # Successful login
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "StrongPass123"},
    )
    assert response.status_code == 200

    # Failed attempts should be reset, so 5 more attempts allowed
    for i in range(4):
        response = client.post(
            "/api/v1/login/access-token",
            data={"username": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 400  # Not locked yet
```

---

### HIGH-03: Invalidate Old Refresh Token on Refresh

**Severity:** 🟠 HIGH
**File:** `app/api/api_v1/endpoints/login.py:47-91`
**Current State:** Old refresh tokens remain valid after refresh

#### Problem
When a refresh token is used to get a new token pair, the old refresh token should be invalidated to prevent token reuse attacks.

#### Solution Specification

1. **Update refresh endpoint** (`app/api/api_v1/endpoints/login.py`)
```python
@router.post("/login/refresh", response_model=Token)
def refresh_token(
    session: deps.SessionDep,
    refresh_token: Annotated[str, Body(embed=True)]
) -> Any:
    """
    Refresh access token.
    Invalidates the used refresh token and issues a new token pair.
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

    # Blacklist the old refresh token immediately
    exp = payload.get("exp")
    if exp:
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        session.add(TokenBlacklist(token=refresh_token, expires_at=expires_at))
        session.commit()

    # Generate new token pair
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
```

2. **Add token rotation detection** (`app/models/user.py`)
```python
class TokenRotation(SQLModel, table=True):
    """Track token families for rotation detection."""
    token_family: str = Field(primary_key=True, index=True)
    user_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_rotated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rotation_count: int = 0
```

#### Acceptance Criteria
- [ ] Old refresh token blacklisted when used
- [ ] New token pair issued
- [ ] Cannot reuse old refresh token
- [ ] Tests verify token rotation

#### Test Cases
```python
def test_refresh_token_rotation(client: TestClient):
    # Create user and login
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPass123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "StrongPass123"},
    )
    old_refresh = login_res.json()["refresh_token"]

    # Use refresh token
    refresh_res = client.post(
        "/api/v1/login/refresh",
        json={"refresh_token": old_refresh},
    )
    assert refresh_res.status_code == 200
    new_refresh = refresh_res.json()["refresh_token"]
    assert new_refresh != old_refresh

    # Try to reuse old refresh token
    response = client.post(
        "/api/v1/login/refresh",
        json={"refresh_token": old_refresh},
    )
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()
```

---

### HIGH-04: Add Security Event Logging

**Severity:** 🟠 HIGH
**Files:** Multiple
**Current State:** No audit trail for security events

#### Solution Specification

1. **Create audit log model** (`app/models/audit.py`)
```python
from datetime import datetime, timezone
from sqlmodel import Field, SQLModel
from enum import Enum


class AuditEventType(str, Enum):
    """Security event types."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    TOKEN_REFRESHED = "token_refreshed"


class AuditLog(SQLModel, table=True):
    """Security audit log."""
    id: int | None = Field(default=None, primary_key=True)
    event_type: str = Field(index=True)
    user_id: int | None = Field(default=None, foreign_key="user.id", index=True)
    email: str | None = Field(default=None, index=True)
    ip_address: str | None = None
    user_agent: str | None = None
    details: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True
    )
```

2. **Create audit utility** (`app/core/audit.py`)
```python
from sqlmodel import Session
from fastapi import Request
from app.models.audit import AuditLog, AuditEventType
from app.models.user import User
import logging

logger = logging.getLogger(__name__)


def log_security_event(
    session: Session,
    event_type: AuditEventType,
    user: User | None = None,
    email: str | None = None,
    request: Request | None = None,
    details: str | None = None,
) -> None:
    """
    Log security event to audit log.

    Args:
        session: Database session
        event_type: Type of security event
        user: User object (if available)
        email: User email (if user object not available)
        request: FastAPI request object
        details: Additional details about the event
    """
    try:
        ip_address = None
        user_agent = None

        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

        audit_entry = AuditLog(
            event_type=event_type.value,
            user_id=user.id if user else None,
            email=email or (user.email if user else None),
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )

        session.add(audit_entry)
        session.commit()

        logger.info(
            f"Security event: {event_type.value} - "
            f"User: {email or (user.email if user else 'unknown')} - "
            f"IP: {ip_address}"
        )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}", exc_info=True)
        # Don't fail the request if audit logging fails
```

3. **Update login endpoint** (`app/api/api_v1/endpoints/login.py`)
```python
from app.core.audit import log_security_event
from app.models.audit import AuditEventType

@router.post("/login/access-token", response_model=Token)
@limiter.limit("5/minute")
def login_access_token(
    request: Request,
    session: deps.SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """OAuth2 compatible token login with audit logging."""
    user = session.exec(select(User).where(User.email == form_data.username)).first()

    if not user or not security.verify_password(form_data.password, user.hashed_password):
        # Log failed attempt
        log_security_event(
            session=session,
            event_type=AuditEventType.LOGIN_FAILED,
            email=form_data.username,
            request=request,
            details="Invalid credentials",
        )
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    if not user.is_active:
        log_security_event(
            session=session,
            event_type=AuditEventType.LOGIN_FAILED,
            user=user,
            request=request,
            details="Account inactive",
        )
        raise HTTPException(status_code=400, detail="Inactive user")

    # Log successful login
    log_security_event(
        session=session,
        event_type=AuditEventType.LOGIN_SUCCESS,
        user=user,
        request=request,
    )

    # ... rest of login logic ...
```

4. **Add audit query endpoint** (`app/api/api_v1/endpoints/users.py`)
```python
from app.models.audit import AuditLog

@router.get("/users/me/audit-log")
def get_my_audit_log(
    session: deps.SessionDep,
    current_user: deps.CurrentUser,
    skip: int = 0,
    limit: int = 50,
) -> list[AuditLog]:
    """Get security audit log for current user."""
    logs = session.exec(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return list(logs)


@router.get("/admin/audit-log")
def get_all_audit_logs(
    session: deps.SessionDep,
    current_user: deps.CurrentSuperUser,
    skip: int = 0,
    limit: int = 100,
    event_type: str | None = None,
) -> list[AuditLog]:
    """Get all security audit logs (admin only)."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if event_type:
        query = query.where(AuditLog.event_type == event_type)

    logs = session.exec(query.offset(skip).limit(limit)).all()
    return list(logs)
```

5. **Create migration**
```bash
make make-migration msg="add audit log table"
```

#### Acceptance Criteria
- [ ] All security events logged to database
- [ ] Captures IP address and user agent
- [ ] Users can view their own audit log
- [ ] Admins can view all audit logs
- [ ] Logging failures don't break requests
- [ ] Tests for audit logging

---

### HIGH-05: Add Email Verification on Signup

**Severity:** 🟠 HIGH
**Files:** `app/api/api_v1/endpoints/users.py`, `app/models/user.py`
**Current State:** Users can signup with any email without verification

#### Solution Specification

1. **Update User model** (`app/models/user.py`)
```python
class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    email_verified: bool = Field(default=False)
    verification_token: str | None = Field(default=None, unique=True, index=True)
    verification_token_expires: datetime | None = None
```

2. **Create email verification utilities** (`app/core/verification.py`)
```python
import secrets
from datetime import datetime, timedelta, timezone
from sqlmodel import Session
from app.models.user import User


def generate_verification_token() -> str:
    """Generate secure verification token."""
    return secrets.token_urlsafe(32)


def create_verification_token(user: User, session: Session) -> str:
    """
    Create verification token for user.

    Returns:
        Verification token
    """
    token = generate_verification_token()
    user.verification_token = token
    user.verification_token_expires = datetime.now(timezone.utc) + timedelta(hours=24)
    session.add(user)
    session.commit()
    return token


def verify_email(token: str, session: Session) -> User | None:
    """
    Verify email using token.

    Returns:
        User if verification successful, None otherwise
    """
    user = session.exec(
        select(User).where(User.verification_token == token)
    ).first()

    if not user:
        return None

    if not user.verification_token_expires:
        return None

    if datetime.now(timezone.utc) > user.verification_token_expires:
        return None

    # Mark as verified
    user.email_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    session.add(user)
    session.commit()

    return user
```

3. **Create email service** (`app/core/email.py`)
```python
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


def send_verification_email(email: str, token: str) -> None:
    """
    Send verification email to user.

    In production, integrate with email service (SendGrid, SES, etc.)
    For now, just log the verification link.
    """
    verification_link = f"{settings.FRONTEND_URL}/verify-email?token={token}"

    # TODO: Integrate with actual email service
    logger.info(
        f"Verification email for {email}:\n"
        f"Click to verify: {verification_link}\n"
        f"Token expires in 24 hours."
    )

    # Example SendGrid integration:
    # from sendgrid import SendGridAPIClient
    # from sendgrid.helpers.mail import Mail
    #
    # message = Mail(
    #     from_email=settings.EMAILS_FROM_EMAIL,
    #     to_emails=email,
    #     subject="Verify your email",
    #     html_content=f'<a href="{verification_link}">Click here to verify</a>'
    # )
    # sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
    # sg.send(message)
```

4. **Update signup endpoint** (`app/api/api_v1/endpoints/users.py`)
```python
from app.core.verification import create_verification_token
from app.core.email import send_verification_email

@router.post("/signup", response_model=UserPublic)
def signup(
    *,
    session: deps.SessionDep,
    user_in: UserCreate,
) -> Any:
    """
    Register a new user.
    Sends verification email.
    """
    user = session.exec(select(User).where(User.email == user_in.email)).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system",
        )

    user = User.model_validate(
        user_in,
        update={"hashed_password": security.get_password_hash(user_in.password)},
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # Generate and send verification token
    token = create_verification_token(user, session)
    send_verification_email(user.email, token)

    return user


@router.post("/verify-email")
def verify_email_endpoint(
    session: deps.SessionDep,
    token: str = Body(..., embed=True),
) -> dict[str, str]:
    """
    Verify email address using token.
    """
    user = verify_email(token, session)

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification token",
        )

    return {"message": "Email verified successfully"}


@router.post("/resend-verification")
def resend_verification(
    session: deps.SessionDep,
    email: EmailStr = Body(..., embed=True),
) -> dict[str, str]:
    """
    Resend verification email.
    """
    user = session.exec(select(User).where(User.email == email)).first()

    if not user:
        # Don't reveal if email exists
        return {"message": "If the email exists, a verification link has been sent"}

    if user.email_verified:
        raise HTTPException(
            status_code=400,
            detail="Email already verified",
        )

    token = create_verification_token(user, session)
    send_verification_email(user.email, token)

    return {"message": "Verification email sent"}
```

5. **Update login to check verification** (`app/api/api_v1/endpoints/login.py`)
```python
@router.post("/login/access-token", response_model=Token)
def login_access_token(...) -> Token:
    # ... existing checks ...

    if not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in",
        )

    # ... rest of login ...
```

6. **Add configuration** (`app/core/config.py`)
```python
class Settings(BaseSettings):
    # ... existing fields ...

    # Email
    FRONTEND_URL: str = "http://localhost:3000"
    EMAILS_ENABLED: bool = False
    EMAILS_FROM_EMAIL: str | None = None
    SENDGRID_API_KEY: str | None = None
```

#### Acceptance Criteria
- [ ] Verification email sent on signup
- [ ] Cannot login without verified email
- [ ] Token expires after 24 hours
- [ ] Can resend verification email
- [ ] Migration adds required fields
- [ ] Tests for verification flow

---

### HIGH-06: Add Password Length Validation

**Severity:** 🟠 HIGH
**File:** Covered in CRIT-04

This is already covered in the CRIT-04 specification above.

---

## Medium Priority Issues (Priority 3)

### MED-01: Add Password Reset Flow

**Severity:** 🟡 MEDIUM
**Files:** New endpoints needed

#### Solution Specification

1. **Update User model** (`app/models/user.py`)
```python
class User(UserBase, table=True):
    # ... existing fields ...
    reset_token: str | None = Field(default=None, unique=True, index=True)
    reset_token_expires: datetime | None = None
```

2. **Create password reset utilities** (`app/core/password_reset.py`)
```python
import secrets
from datetime import datetime, timedelta, timezone
from sqlmodel import Session, select
from app.models.user import User
from app.core.security import get_password_hash


def generate_reset_token() -> str:
    """Generate secure password reset token."""
    return secrets.token_urlsafe(32)


def create_reset_token(email: str, session: Session) -> str | None:
    """
    Create password reset token for user.

    Returns:
        Reset token if user found, None otherwise
    """
    user = session.exec(select(User).where(User.email == email)).first()

    if not user:
        return None

    token = generate_reset_token()
    user.reset_token = token
    user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    session.add(user)
    session.commit()

    return token


def reset_password(token: str, new_password: str, session: Session) -> bool:
    """
    Reset password using token.

    Returns:
        True if successful, False otherwise
    """
    user = session.exec(
        select(User).where(User.reset_token == token)
    ).first()

    if not user:
        return False

    if not user.reset_token_expires:
        return False

    if datetime.now(timezone.utc) > user.reset_token_expires:
        return False

    # Reset password
    user.hashed_password = get_password_hash(new_password)
    user.reset_token = None
    user.reset_token_expires = None
    session.add(user)
    session.commit()

    return True
```

3. **Add password reset endpoints** (`app/api/api_v1/endpoints/login.py`)
```python
from app.core.password_reset import create_reset_token, reset_password

@router.post("/password-reset/request")
@limiter.limit("3/hour")
def request_password_reset(
    request: Request,
    session: deps.SessionDep,
    email: EmailStr = Body(..., embed=True),
) -> dict[str, str]:
    """
    Request password reset email.
    Rate limited to prevent abuse.
    """
    token = create_reset_token(email, session)

    if token:
        # TODO: Send email with reset link
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        logger.info(f"Password reset link for {email}: {reset_link}")

    # Always return success to prevent email enumeration
    return {
        "message": "If the email exists, a password reset link has been sent"
    }


@router.post("/password-reset/confirm")
def confirm_password_reset(
    session: deps.SessionDep,
    token: str = Body(...),
    new_password: str = Body(..., min_length=8),
) -> dict[str, str]:
    """
    Reset password using token.
    """
    # Validate password strength
    security.validate_password_strength(new_password)

    success = reset_password(token, new_password, session)

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    return {"message": "Password reset successfully"}
```

#### Acceptance Criteria
- [ ] Users can request password reset
- [ ] Reset token expires after 1 hour
- [ ] Rate limited to prevent abuse
- [ ] Cannot enumerate valid emails
- [ ] Password validation applied
- [ ] Tests for reset flow

---

### MED-02: Add JWT Token ID (jti) Claim

**Severity:** 🟡 MEDIUM
**File:** `app/core/security.py`

#### Solution Specification

1. **Update token creation** (`app/core/security.py`)
```python
import uuid

def create_access_token(
    subject: Union[str, Any],
    expires_delta: timedelta = None,
    token_type: str = "access"
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "jti": str(uuid.uuid4()),  # Unique token ID
        "type": token_type,  # "access" or "refresh"
    }
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt
```

2. **Update TokenData model** (`app/models/user.py`)
```python
class TokenData(SQLModel):
    sub: str | None = None
    jti: str | None = None
    type: str | None = None
```

3. **Validate token type** (`app/api/deps.py`)
```python
def get_current_user(session: SessionDep, token: TokenDep) -> User:
    # ... existing blacklist check ...

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenData(**payload)

        # Verify token type
        if token_data.type != "access":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token type",
            )
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    # ... rest of validation ...
```

#### Acceptance Criteria
- [ ] All tokens include jti claim
- [ ] Token type validated (access vs refresh)
- [ ] Unique ID for each token
- [ ] Tests verify jti presence

---

### MED-03: Add Security Headers Middleware

**Severity:** 🟡 MEDIUM
**File:** `app/main.py`

#### Solution Specification

1. **Create security headers middleware** (`app/core/security_headers.py`)
```python
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Strict Transport Security (HTTPS only)
        # Only add in production with HTTPS
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response
```

2. **Add to application** (`app/main.py`)
```python
from app.core.security_headers import SecurityHeadersMiddleware

app.add_middleware(SecurityHeadersMiddleware)
```

#### Acceptance Criteria
- [ ] All security headers added
- [ ] Tests verify headers present
- [ ] Documentation updated

---

### MED-04: Implement Admin User Management Endpoints

**Severity:** 🟡 MEDIUM
**File:** `app/api/api_v1/endpoints/users.py`

#### Solution Specification

```python
@router.get("/", response_model=list[UserPublic])
def list_users(
    session: deps.SessionDep,
    current_user: deps.CurrentSuperUser,
    skip: int = 0,
    limit: int = 100,
) -> list[User]:
    """
    List all users (admin only).
    """
    users = session.exec(select(User).offset(skip).limit(limit)).all()
    return list(users)


@router.get("/{user_id}", response_model=UserPublic)
def get_user(
    session: deps.SessionDep,
    user_id: int,
    current_user: deps.CurrentSuperUser,
) -> User:
    """
    Get user by ID (admin only).
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserPublic)
def update_user(
    session: deps.SessionDep,
    user_id: int,
    user_in: UserUpdate,
    current_user: deps.CurrentSuperUser,
) -> User:
    """
    Update user (admin only).
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check email uniqueness if changing email
    if user_in.email and user_in.email != user.email:
        existing = session.exec(
            select(User).where(User.email == user_in.email)
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists"
            )

    user_data = user_in.model_dump(exclude_unset=True)
    user.sqlmodel_update(user_data)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(
    session: deps.SessionDep,
    user_id: int,
    current_user: deps.CurrentSuperUser,
) -> dict[str, str]:
    """
    Delete user (admin only).
    Cannot delete yourself.
    """
    if user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account"
        )

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    session.delete(user)
    session.commit()
    return {"message": "User deleted successfully"}
```

#### Acceptance Criteria
- [ ] Admin can list all users
- [ ] Admin can view any user
- [ ] Admin can update any user
- [ ] Admin can delete users (except self)
- [ ] Pagination support
- [ ] Tests for all endpoints

---

### MED-05: Add Health Check Endpoint

**Severity:** 🟡 MEDIUM
**File:** `app/main.py`

#### Solution Specification

```python
from sqlmodel import text

@app.get("/health")
def health_check(session: deps.SessionDep) -> dict[str, str]:
    """
    Health check endpoint for monitoring.
    Returns 200 if service is healthy.
    """
    try:
        # Check database connectivity
        session.exec(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Service unhealthy: {str(e)}"
        )


@app.get("/health/ready")
def readiness_check() -> dict[str, str]:
    """
    Readiness check for Kubernetes.
    Returns 200 when service is ready to accept traffic.
    """
    return {"status": "ready"}


@app.get("/health/live")
def liveness_check() -> dict[str, str]:
    """
    Liveness check for Kubernetes.
    Returns 200 if service is alive.
    """
    return {"status": "alive"}
```

#### Acceptance Criteria
- [ ] Health endpoint checks database
- [ ] Readiness endpoint for K8s
- [ ] Liveness endpoint for K8s
- [ ] Returns appropriate status codes
- [ ] Tests for health checks

---

### MED-06-09: Database Optimization, Request Tracking, etc.

**Note:** Due to length constraints, I'll provide abbreviated specifications for the remaining items. These follow similar patterns to above.

**MED-06: Database Indexes**
- Add index on `token_blacklist.expires_at`
- Add composite index on `user(email, is_active)`
- Add index on `audit_log(created_at, event_type)`

**MED-07: Connection Pooling**
```python
# app/db/session.py
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)
```

**MED-08: Request ID Tracking**
- Add middleware to generate request ID
- Include in logs and error responses
- Add to audit log entries

---

## Low Priority Issues (Priority 4)

### LOW-01: Refactor Duplicate Code

**File:** `app/api/api_v1/endpoints/users.py`

#### Solution
Create shared function:
```python
def _create_user_from_input(
    session: Session,
    user_in: UserCreate,
) -> User:
    """Shared user creation logic."""
    existing = session.exec(
        select(User).where(User.email == user_in.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists",
        )

    user = User.model_validate(
        user_in,
        update={"hashed_password": security.get_password_hash(user_in.password)},
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
```

---

### LOW-02: Add Comprehensive Docstrings

Add detailed docstrings to all functions following Google style:
```python
def get_current_user(session: SessionDep, token: TokenDep) -> User:
    """
    Get current authenticated user from JWT token.

    Validates the token is not blacklisted, decodes the JWT,
    verifies the user exists and is active.

    Args:
        session: Database session dependency
        token: JWT token from Authorization header

    Returns:
        User object if authentication successful

    Raises:
        HTTPException: 401 if token is blacklisted
        HTTPException: 403 if token is invalid
        HTTPException: 404 if user not found
        HTTPException: 400 if user is inactive
    """
```

---

### LOW-03: Custom Exception Classes

**File:** `app/core/exceptions.py`
```python
class UserNotFoundError(Exception):
    """User not found in database."""
    pass

class InvalidCredentialsError(Exception):
    """Invalid login credentials."""
    pass

class AccountLockedError(Exception):
    """Account is locked due to failed attempts."""
    def __init__(self, lockout_minutes: int):
        self.lockout_minutes = lockout_minutes
        super().__init__(f"Account locked for {lockout_minutes} minutes")
```

---

### LOW-04: Standardize HTTP Status Codes

Create constants:
```python
# app/core/constants.py
class HTTPStatus:
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
```

---

### LOW-05: Add Pagination Support

**File:** `app/models/common.py`
```python
class PaginatedResponse(SQLModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int
```

---

### LOW-06: Remove --reload from Production Dockerfile

**File:** `Dockerfile`
```dockerfile
# Change from:
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80", "--reload"]

# To:
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
```

---

### LOW-07: Add Error Response Models

**File:** `app/models/responses.py`
```python
class ErrorResponse(SQLModel):
    detail: str
    error_code: str | None = None
    request_id: str | None = None


class ValidationErrorResponse(SQLModel):
    detail: list[dict[str, Any]]
    error_code: str = "VALIDATION_ERROR"
```

---

## Testing Requirements

### Test Coverage Targets
- **Critical fixes:** 100% test coverage required
- **High priority:** 90% test coverage required
- **Medium priority:** 80% test coverage required
- **Low priority:** 70% test coverage required

### Test Types Required
1. **Unit tests** - Test individual functions in isolation
2. **Integration tests** - Test endpoint flows end-to-end
3. **Security tests** - Test security controls (rate limiting, lockout, etc.)
4. **Negative tests** - Test error conditions and edge cases

### Example Test Structure
```python
# tests/test_security.py
def test_rate_limiting_login():
    """Test that login endpoint enforces rate limits."""
    pass

def test_account_lockout():
    """Test that account locks after max failed attempts."""
    pass

def test_password_complexity():
    """Test that weak passwords are rejected."""
    pass

def test_cors_enforcement():
    """Test that CORS policy is enforced."""
    pass
```

---

## Deployment Checklist

### Pre-Deployment
- [ ] All critical issues resolved
- [ ] All tests passing
- [ ] Code review completed
- [ ] Security scan performed
- [ ] Documentation updated

### Environment Configuration
- [ ] Generate secure `SECRET_KEY` (64+ characters)
- [ ] Set strong `POSTGRES_PASSWORD`
- [ ] Configure `BACKEND_CORS_ORIGINS` for production domains
- [ ] Set up Redis for rate limiting
- [ ] Configure email service (SendGrid/SES)
- [ ] Set `FRONTEND_URL` to production URL
- [ ] Enable `EMAILS_ENABLED=true`

### Database
- [ ] Run all migrations
- [ ] Create initial superuser
- [ ] Backup strategy in place
- [ ] Connection pooling configured

### Security
- [ ] HTTPS enforced (reverse proxy)
- [ ] Security headers enabled
- [ ] Rate limiting active
- [ ] Audit logging enabled
- [ ] Token cleanup job running

### Monitoring
- [ ] Health check endpoints monitored
- [ ] Audit log retention policy
- [ ] Failed login alerts configured
- [ ] Error tracking (Sentry/similar)

---

## Implementation Order

### Phase 1 (Week 1) - Critical Security
1. CRIT-01: CORS restriction
2. CRIT-02: Protect user creation endpoint
3. CRIT-03: Rate limiting
4. CRIT-04: Password complexity

### Phase 2 (Week 2) - Account Security
1. HIGH-01: Token blacklist cleanup
2. HIGH-02: Account lockout
3. HIGH-03: Refresh token rotation
4. HIGH-04: Security event logging

### Phase 3 (Week 3) - User Experience
1. HIGH-05: Email verification
2. MED-01: Password reset flow
3. MED-02: JWT token IDs
4. MED-03: Security headers

### Phase 4 (Week 4) - Admin & Operations
1. MED-04: Admin user management
2. MED-05: Health checks
3. MED-06-08: Database optimization
4. Code quality improvements (LOW priority items)

---

## Success Criteria

### Security Posture
- ✅ No critical vulnerabilities in security scan
- ✅ All authentication endpoints protected by rate limiting
- ✅ Account lockout prevents brute force attacks
- ✅ CORS properly configured for production
- ✅ All security events logged and monitored

### Code Quality
- ✅ Test coverage >80% overall
- ✅ All linting checks passing
- ✅ No code duplication issues
- ✅ Comprehensive documentation

### Functionality
- ✅ Complete user authentication flow
- ✅ Email verification working
- ✅ Password reset functional
- ✅ Admin user management operational
- ✅ Audit trail for security events

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [FastAPI Security Best Practices](https://fastapi.tiangolo.com/tutorial/security/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-04
**Status:** Ready for Implementation
