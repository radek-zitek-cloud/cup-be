# Cup Backend

A scalable, high-performance backend service built with FastAPI and PostgreSQL.

## Documentation

Full documentation is available in the `docs/` directory. You can also run it locally:

```bash
uv run mkdocs serve
```

Then open [http://localhost:8000](http://localhost:8000) (or the port specified by mkdocs).

## Quick Start

1.  Copy the environment file:
    ```bash
    cp .env.example .env
    ```

2.  Start the containers:
    ```bash
    docker compose up -d --build
    ```

3.  Run migrations:
    ```bash
    docker compose exec web uv run alembic upgrade head
    ```

The API will be available at [http://localhost:8000](http://localhost:8000).
