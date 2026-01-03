# Architecture & Decisions

## Technology Stack

-   **Language:** Python 3.12+
-   **Framework:** FastAPI
-   **Database:** PostgreSQL 18
-   **ORM:** SQLModel (SQLAlchemy + Pydantic)
-   **Migrations:** Alembic
-   **Package Manager:** uv
-   **Containerization:** Docker

## Project Structure

```
cup-be/
├── alembic/                # Database migrations
├── app/
│   ├── api/                # API Endpoints and dependencies
│   │   ├── api_v1/         # Version 1 API
│   │   └── deps.py         # Dependencies (DB, Auth)
│   ├── core/               # Core config and security
│   ├── db/                 # Database connection and session
│   ├── models/             # SQLModel database models
│   └── main.py             # Application entry point
├── tests/                  # Tests
├── docs/                   # Documentation
├── .env                    # Environment variables (ignored by git)
├── .env.example            # Example environment variables
├── Dockerfile              # Docker image definition
├── docker-compose.yml      # Docker Compose configuration
├── mkdocs.yml              # Documentation configuration
└── pyproject.toml          # Project metadata and dependencies
```

## Design Decisions

### 1. SQLModel
We chose SQLModel because it combines SQLAlchemy and Pydantic, reducing code duplication by allowing the same models to be used for both database schemas and API validation.

### 2. Alembic
Alembic provides robust database migration capabilities, essential for evolving the database schema over time without data loss.

### 3. Docker & Docker Compose
Containerization ensures that the development environment matches production as closely as possible, minimizing "it works on my machine" issues. `docker-compose` simplifies managing the multi-container setup (web + db).

### 4. uv
`uv` is used for package management due to its speed and efficiency in resolving and installing dependencies.

### 5. Environment Variables
Configuration is managed via environment variables loaded from a `.env` file using `pydantic-settings`. This adheres to the 12-factor app methodology and improves security.
