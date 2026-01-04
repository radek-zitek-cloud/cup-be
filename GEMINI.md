# cup-be (Cup Backend)

## Project Overview
`cup-be` is a high-performance backend service built with Python and FastAPI. It uses PostgreSQL as its primary data store, interacting via SQLModel. The project is containerized using Docker and utilizes `uv` for modern Python dependency management.

### Key Technologies
*   **Framework:** FastAPI
*   **Database:** PostgreSQL (v18), Redis (v8)
*   **ORM:** SQLModel
*   **Migrations:** Alembic
*   **Authentication:** Python-Jose (JWT) with Access & Refresh tokens, Bcrypt. **Token invalidation on logout via database blacklist.**
*   **Dependency Management:** uv
*   **Documentation:** MkDocs (Material theme)

## Architecture & Structure
*   `app/`: Main application source code.
    *   `main.py`: Application entry point.
    *   `api/`: Route handlers (endpoints) and dependencies.
    *   `core/`: Core configuration (`config.py`), security logic, and logging.
    *   `db/`: Database session management.
    *   `middleware/`: Custom middleware (logging, etc.).
    *   `models/`: SQLModel data models.
*   `alembic/`: Database migration scripts.
*   `scripts/`: Utility scripts for building, releasing, etc.
*   `tests/`: Pytest test suite (including `test_auth.py` for comprehensive auth testing).
*   `CHANGELOG.md`: Record of all notable changes.
*   `docker-compose.yml`: Local development environment definition.
*   `pyproject.toml`: Project configuration and dependencies.

## API Endpoints (Auth & Users)
*   `POST /api/v1/users/signup`: Public user registration.
*   `POST /api/v1/login/access-token`: Login to receive access and refresh tokens.
*   `POST /api/v1/login/refresh`: Use refresh token to get new tokens.
*   `POST /api/v1/login/logout`: Logout endpoint.
*   `GET /api/v1/users/me`: Retrieve current user profile.
*   `PATCH /api/v1/users/me`: Update current user profile.
*   `PATCH /api/v1/users/me/password`: Change current user password.

## Setup & Development

### Prerequisites
*   Docker & Docker Compose
*   [uv](https://github.com/astral-sh/uv) (recommended for local python management)

### Initial Setup
1.  **Environment Variables:**
    ```bash
    cp .env.example .env
    # Edit .env with your local configuration if necessary
    ```

### Running the Application

**Option 1: Docker (Recommended)**
```bash
# Build and start services
docker compose up -d --build

# View logs
docker compose logs -f backend
```
The API will be available at [http://localhost:8000](http://localhost:8000).

**Option 2: Local Development**
1.  Install dependencies:
    ```bash
    uv sync
    ```
2.  Start the database (via Docker):
    ```bash
    docker compose up -d db
    ```
3.  Run the server:
    ```bash
    uv run uvicorn app.main:app --reload
    ```

### Database Management
Migrations are handled by Alembic. **They are automatically run on application startup** via a FastAPI lifespan event.

*   **Manual Migrations:**
    ```bash
    # Via Docker
    make docker-migrate
    
    # Locally
    make migrate
    ```

*   **Create a New Migration:**
    ```bash
    uv run alembic revision --autogenerate -m "Description of change"
    ```

### Testing
Run the test suite using `pytest`:
```bash
uv run pytest
```

Or run the full check (lint + format check + tests):
```bash
make check
```

### Documentation
The project includes MkDocs documentation.
```bash
make docs
```
Access docs at http://localhost:8008.

### Building
To build the Docker image with the version specified in `pyproject.toml`:
```bash
make build
```