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


def test_signup(client: TestClient):
    response = client.post(
        "/api/v1/users/signup",
        json={
            "email": "test@example.com",
            "password": "password123",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["full_name"] == "Test User"
    assert data["is_super"] is False
    assert "id" in data


def test_login(client: TestClient):
    # First signup
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )

    # Then login
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_get_me(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    token = login_res.json()["access_token"]

    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"


def test_refresh_token(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    refresh_token = login_res.json()["refresh_token"]

    response = client.post(
        "/api/v1/login/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_update_me(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={
            "email": "test@example.com",
            "password": "password123",
            "full_name": "Old Name",
        },
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    token = login_res.json()["access_token"]

    response = client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"full_name": "New Name"},
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "New Name"


def test_update_me_is_super_no_effect(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    token = login_res.json()["access_token"]

    # Attempt to set is_super to True
    response = client.patch(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"is_super": True},
    )
    # Depending on how Pydantic handles extra fields, it might succeed (ignoring extra) or fail.
    # SQLModel/Pydantic by default ignores extra fields if not configured otherwise.
    assert response.status_code == 200
    assert response.json()["is_super"] is False


def test_update_password(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={"email": "test@example.com", "password": "password123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "password123"},
    )
    token = login_res.json()["access_token"]

    response = client.patch(
        "/api/v1/users/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "password123", "new_password": "newpassword123"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated successfully"

    # Try login with new password
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": "test@example.com", "password": "newpassword123"},
    )
    assert response.status_code == 200


def test_logout(client: TestClient):
    client.post(
        "/api/v1/users/signup",
        json={"email": "logout@example.com", "password": "password123"},
    )
    login_res = client.post(
        "/api/v1/login/access-token",
        data={"username": "logout@example.com", "password": "password123"},
    )
    token = login_res.json()["access_token"]
    
    # Verify we can access protected endpoint
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    
    # Logout
    response = client.post(
        "/api/v1/login/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}
    
    # Verify we can NO LONGER access protected endpoint
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has been revoked"
