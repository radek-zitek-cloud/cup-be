# API Documentation

The API is built using FastAPI, which provides automatic interactive documentation.

## Interactive Docs

Once the application is running, you can access the interactive documentation at:

-   **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
-   **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Key Endpoints

### Authentication

-   `POST /api/v1/login/access-token`: Login to get an access token.
    -   **Body:** `username` (email) and `password`.
    -   **Returns:** JSON Web Token (JWT).

### Users

-   `POST /api/v1/users/`: Register a new user.
    -   **Body:** `email`, `password`, `full_name`.
-   `GET /api/v1/users/me`: Get current user details.
    -   **Headers:** `Authorization: Bearer <token>`

### Health Check

-   `GET /`: Returns a welcome message, useful for health checks.
