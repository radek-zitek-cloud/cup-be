# Cup Backend

A scalable, high-performance backend service built with FastAPI and PostgreSQL.

## Documentation

Full documentation is available in the `docs/` directory. You can also run it locally:

```bash
make docs
```

Then open [http://localhost:8008](http://localhost:8008).

## Quick Start

1.  Copy the environment file:
    ```bash
    cp .env.example .env
    ```

2.  Start the containers:
    ```bash
    make up
    ```

3.  Run migrations:
    ```bash
    make docker-migrate
    ```

The API will be available at [http://localhost:8000](http://localhost:8000).

---
*Tip: Use `make help` to see all available development commands.*
