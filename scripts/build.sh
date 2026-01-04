#!/bin/bash
set -e

# Extract version from pyproject.toml
VERSION=$(grep -m 1 'version = "' pyproject.toml | sed -E 's/version = "(.*)"/\1/')

if [ -z "$VERSION" ]; then
  echo "Error: Could not extract version from pyproject.toml"
  exit 1
fi

echo "Building Docker image for version: $VERSION"

# Build with specific tag
TAG=$VERSION docker compose build web

# Also tag as latest
TAG=latest docker compose build web

echo "Successfully built cup-be:$VERSION and cup-be:latest"
