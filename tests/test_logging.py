import os

# Set environment to test BEFORE importing anything from app
os.environ["ENVIRONMENT"] = "test"

import logging
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, StaticPool
from app.main import app
from app.api.deps import get_db
from app.core.logging import mask_sensitive_data

# Setup in-memory SQLite for testing
DATABASE_URL = "sqlite://"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@pytest.fixture(name="session")
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_db_override():
        return session

    app.dependency_overrides[get_db] = get_db_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_mask_sensitive_data():
    data = {
        "email": "test@example.com",
        "password": "secretpassword",
        "nested": {"token": "sensitive_token", "safe": "public_data"},
    }
    masked = mask_sensitive_data(data)
    assert masked["email"] == "test@example.com"
    assert masked["password"] == "***MASKED***"
    assert masked["nested"]["token"] == "***MASKED***"
    assert masked["nested"]["safe"] == "public_data"


def test_mask_authorization_header():
    header = "Bearer some_long_token_here"
    masked = mask_sensitive_data(header)
    assert masked == "Bearer ***MASKED***"


def test_request_logging_middleware(client: TestClient, capsys):
    client.post(
        "/api/v1/users/signup",
        json={
            "email": "logging_test@example.com",
            "password": "StrongPassword123",
            "full_name": "Logging Test",
        },
    )

    captured = capsys.readouterr()

    # Check that we have the request log in stdout
    assert "Incoming request: POST" in captured.out
    assert "/api/v1/users/signup" in captured.out
    assert "StrongPassword123" not in captured.out
    assert "***MASKED***" in captured.out

    # Check that we have the completion log in stdout
    assert "Completed request: POST" in captured.out
    assert "Status: 200" in captured.out or "Status: 400" in captured.out
