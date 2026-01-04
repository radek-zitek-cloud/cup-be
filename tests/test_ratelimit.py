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


@pytest.fixture(name="client", autouse=True)
def client_fixture(session: Session):
    # Enable limiter for these tests
    from app.core.ratelimit import limiter

    limiter.enabled = True

    def get_db_override():
        return session

    app.dependency_overrides[get_db] = get_db_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()
    # Disable it back for other tests
    limiter.enabled = False


def test_login_rate_limit(client: TestClient):
    # Make login attempts beyond the limit
    # Default is 5/minute

    email = "ratelimit@example.com"
    password = "password123"

    # First 5 attempts (regardless of success/fail)
    for _ in range(5):
        client.post(
            "/api/v1/login/access-token",
            data={"username": email, "password": password},
        )

    # 6th attempt should be rate limited
    response = client.post(
        "/api/v1/login/access-token",
        data={"username": email, "password": password},
    )

    assert response.status_code == 429
    assert "too many requests" in response.json()["detail"].lower()
