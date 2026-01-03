# Release Process

This project uses a scripted approach to manage semantic versioning, git tagging, and GitHub releases.

## Prerequisites

-   You must have write access to the main branch.
-   `gh` (GitHub CLI) must be installed and authenticated.
-   `uv` must be installed.
-   Git working directory must be clean.

## Creating a Release

To create a new release, use the `scripts/release.sh` script.

### Syntax

```bash
./scripts/release.sh [major|minor|patch]
```

### Examples

**Patch Release (0.1.0 -> 0.1.1):**
```bash
./scripts/release.sh patch
```

**Minor Release (0.1.0 -> 0.2.0):**
```bash
./scripts/release.sh minor
```

**Major Release (0.1.0 -> 1.0.0):**
```bash
./scripts/release.sh major
```

## What the script does

1.  **Bumps the version** in `pyproject.toml` using `scripts/bump_version.py`.
2.  **Syncs dependencies** (`uv sync`) to ensure `uv.lock` is consistent.
3.  **Runs tests** (`uv run pytest`) to ensure the release is stable.
4.  **Commits** the changes to `pyproject.toml` and `uv.lock`.
5.  **Creates a Git Tag** (e.g., `v0.1.1`).
6.  **Pushes** the commit and the tag to `origin/main`.
7.  **Creates a GitHub Release** using the generated notes feature of GitHub.
