#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./scripts/release.sh [major|minor|patch]"
  exit 1
fi

BUMP_TYPE=$1

# Ensure working directory is clean
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: Working directory is not clean. Commit or stash changes first."
  exit 1
fi

echo "Bumping $BUMP_TYPE version..."
NEW_VERSION=$(./scripts/bump_version.sh "$BUMP_TYPE")

if [ -z "$NEW_VERSION" ]; then
    echo "Error: Failed to bump version."
    exit 1
fi

echo "New version: $NEW_VERSION"

# Update lock file if necessary (optional, but good practice to sync)
echo "Syncing dependencies..."
uv sync

# Run tests
echo "Running tests..."
ENVIRONMENT=test uv run pytest

# Commit change
echo "Committing version bump..."
git add pyproject.toml uv.lock
git commit -m "Bump version to $NEW_VERSION"

# Tag
TAG="v$NEW_VERSION"
echo "Tagging $TAG..."
git tag -a "$TAG" -m "Release $TAG"

# Push
echo "Pushing changes and tag..."
git push origin main
git push origin "$TAG"

# Create GitHub Release
echo "Creating GitHub Release..."
gh release create "$TAG" --generate-notes

echo "Release $TAG created successfully!"
