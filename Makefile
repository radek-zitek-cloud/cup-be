.PHONY: help up down restart logs build install dev test lint format check migrate make-migration docs bump-patch bump-minor bump-major release-patch release-minor release-major git-status git-push

# Default target
help:
	@echo "Available commands:"
	@echo "  Docker:"
	@echo "    make up              - Start containers in detached mode"
	@echo "    make down            - Stop and remove containers"
	@echo "    make restart         - Restart containers"
	@echo "    make logs            - Follow container logs"
	@echo "    make build           - Build Docker images"
	@echo ""
	@echo "  Local Development:"
	@echo "    make install         - Install dependencies with uv"
	@echo "    make dev             - Run local development server"
	@echo "    make test            - Run tests with pytest"
	@echo "    make lint            - Check linting with ruff"
	@echo "    make format          - Format code with ruff"
	@echo "    make check           - Run lint, format check, and tests"
	@echo ""
	@echo "  Database:"
	@echo "    make migrate         - Run Alembic migrations (local)"
	@echo "    make docker-migrate  - Run Alembic migrations (in docker)"
	@echo "    make make-migration  - Create a new migration (usage: make make-migration msg=\"message\")"
	@echo ""
	@echo "  Documentation:"
	@echo "    make docs            - Serve MkDocs locally"
	@echo ""
	@echo "  Version & Release:"
	@echo "    make bump-patch      - Bump patch version (0.0.X)"
	@echo "    make bump-minor      - Bump minor version (0.X.0)"
	@echo "    make bump-major      - Bump major version (X.0.0)"
	@echo "    make release-patch   - Create patch release (bump, test, commit, tag, push, gh release)"
	@echo "    make release-minor   - Create minor release"
	@echo "    make release-major   - Create major release"
	@echo ""
	@echo "  Git:"
	@echo "    make git-status      - Show git status"
	@echo "    make git-push        - Push changes to origin"

# Docker
up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

build:
	./scripts/build.sh

# Local Development
install:
	uv sync

dev:
	uv run uvicorn app.main:app --reload

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

check: lint test
	uv run ruff format --check .

# Database
migrate:
	uv run alembic upgrade head

docker-migrate:
	docker compose exec backend uv run alembic upgrade head

make-migration:
	@if [ -z "$(msg)" ]; then echo "Error: msg is required. Usage: make make-migration msg=\"message\""; exit 1; fi
	uv run alembic revision --autogenerate -m "$(msg)"

# Documentation
docs:
	uv run mkdocs serve -a localhost:8008

# Version & Release
bump-patch:
	./scripts/bump_version.sh patch

bump-minor:
	./scripts/bump_version.sh minor

bump-major:
	./scripts/bump_version.sh major

release-patch:
	./scripts/release.sh patch

release-minor:
	./scripts/release.sh minor

release-major:
	./scripts/release.sh major

# Git
git-status:
	git status

git-push:
	git push
