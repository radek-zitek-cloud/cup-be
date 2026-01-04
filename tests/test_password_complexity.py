import os

# Set environment to test BEFORE importing anything from app
os.environ["ENVIRONMENT"] = "test"

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, StaticPool
from app.main import app
from app.api.deps import get_db

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


def test_signup_weak_password(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "weak"},
    )
    assert response.status_code == 422
    # The message comes from our validator as a string
    assert "at least 8 characters" in str(response.json()["detail"]).lower()


def test_signup_no_uppercase(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "weakpassword123"},
    )
    assert response.status_code == 422
    assert "uppercase" in response.json()["detail"].lower()


def test_signup_no_lowercase(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "WEAKPASSWORD123"},
    )
    assert response.status_code == 422
    assert "lowercase" in response.json()["detail"].lower()


def test_signup_no_digit(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "WeakPassword"},
    )
    assert response.status_code == 422
    assert "digit" in response.json()["detail"].lower()


def test_signup_strong_password(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "StrongPassword123"},
    )
    assert response.status_code == 200
