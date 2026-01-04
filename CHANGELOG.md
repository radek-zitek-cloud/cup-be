# Changelog

All notable changes to this project will be documented in this file.

## [0.1.4] - 2026-01-03

### Changed
- Renamed Docker service from `web` to `backend`.
- Set explicit Docker container name to `backend-1`.
- Renamed Docker image to `cup-be`.
- Updated all scripts and documentation to reflect service renaming.

### Added
- Integrated CORS middleware to allow cross-origin requests.
- **Implemented Request Logging Middleware with sensitive data masking.**
- **Added `app/core/logging.py` for centralized logging configuration.**

## [0.1.3] - 2026-01-03

### Added
- Integrated `ruff` for linting and formatting.
- Added `make lint`, `make format`, and `make check` targets to the Makefile.
- Added `is_super` boolean field to the User model.
- Programmatic Alembic migrations on application startup via FastAPI lifespan.
- Comprehensive authentication tests in `tests/test_auth.py`.

### Changed
- Migrated `bump_version.py` to `bump_version.sh`.
- Prevented users from self-elevating to `is_super` via the `/me` endpoint.

### Fixed
- Addressed `crypt` deprecation warning by replacing `passlib` with `bcrypt`.
- Fixed `is_super` migration to handle existing rows with a `server_default`.

## [0.1.2] - 2026-01-03

### Added
- Full authentication suite: Signup, Login (Access/Refresh tokens), Refresh, Logout.
- User profile management: Get Me, Update Me, Change Password.
- Comprehensive `Makefile` for developer productivity.
- `GEMINI.md` for project context and instructions.

## [0.1.1] - 2026-01-03

### Added
- Initial release scripts and semantic versioning setup.
- Docker tagging strategy.
- MkDocs documentation structure.
