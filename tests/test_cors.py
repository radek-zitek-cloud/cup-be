from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings


def test_cors_allowed_origin():
    client = TestClient(app)
    # Use an origin from the default settings
    origin = "http://localhost:3000"
    if (
        isinstance(settings.BACKEND_CORS_ORIGINS, list)
        and origin not in settings.BACKEND_CORS_ORIGINS
    ):
        settings.BACKEND_CORS_ORIGINS.append(origin)

    response = client.options(
        "/api/v1/users/me",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_cors_forbidden_origin():
    client = TestClient(app)
    origin = "http://evil.com"

    response = client.options(
        "/api/v1/users/me",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    # FastAPI/Starlette CORSMiddleware returns 400 or just doesn't include the headers if origin not allowed
    # For a preflight request with an invalid origin, it should not have the AC-Allow-Origin header
    assert response.headers.get("access-control-allow-origin") is None
