#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./scripts/bump_version.sh [major|minor|patch]"
  exit 1
fi

BUMP_TYPE=$1
PYPROJECT="pyproject.toml"

# Extract current version
VERSION=$(grep -m 1 '^version = "' "$PYPROJECT" | cut -d '"' -f 2)

if [ -z "$VERSION" ]; then
  echo "Error: Could not find version in $PYPROJECT" >&2
  exit 1
fi

# Split version into components
IFS='.' read -r major minor patch <<< "$VERSION"

case "$BUMP_TYPE" in
  major)
    major=$((major + 1))
    minor=0
    patch=0
    ;;
  minor)
    minor=$((minor + 1))
    patch=0
    ;;
  patch)
    patch=$((patch + 1))
    ;;  *)
    echo "Error: Invalid part '$BUMP_TYPE'. Use major, minor, or patch." >&2
    exit 1
    ;;esac

NEW_VERSION="${major}.${minor}.${patch}"

# Update pyproject.toml
sed -i "s/^version = \"$VERSION\"/version = \"$NEW_VERSION\"/" "$PYPROJECT"

echo "$NEW_VERSION"