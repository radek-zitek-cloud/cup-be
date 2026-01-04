# Setup & Installation

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [uv](https://github.com/astral-sh/uv) (Optional, but recommended for local python management)

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/radek-zitek-cloud/cup-be.git
    cd cup-be
    ```

2.  **Environment Setup:**

    Copy the example environment file and update it with your own values (or use the defaults for local dev):

    ```bash
    cp .env.example .env
    ```

    > **Important:** In production, generate a secure `SECRET_KEY` and update the `POSTGRES_PASSWORD`.

3.  **Start the application:**

    ```bash
    docker compose up -d --build
    ```

    This command will build the Docker image and start the containers (backend and db).

4.  **Run Migrations:**

    Apply the database migrations to set up the schema:

    ```bash
    docker compose exec backend uv run alembic upgrade head
    ```

## Development

-   The API is available at `http://localhost:8000`.
-   Automatic documentation (Swagger UI) is available at `http://localhost:8000/docs`.
-   Alternative documentation (ReDoc) is available at `http://localhost:8000/redoc`.

## Documentation

To run the documentation locally for development:

```bash
make docs
```

Then open [http://localhost:8008](http://localhost:8008).

## Testing

To run tests inside the container:

```bash
docker compose exec backend uv run pytest
```
