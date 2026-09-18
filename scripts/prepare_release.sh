#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: scripts/prepare_release.sh MAJOR.MINOR.PATCH"
    exit 1
fi

VERSION="$1"

echo "Preparing release ${VERSION}"

uv run python scripts/set_version.py "${VERSION}"

echo
echo "Refreshing Python lockfile..."
uv lock

echo
echo "Refreshing Rust lockfile..."
cargo check --manifest-path src-tauri/Cargo.toml

echo
echo "Refreshing pnpm lockfile..."
pnpm install --lockfile-only

echo
echo "Running basic validation..."
uv run ruff check .
uv run python -m compileall src/openbis_upload_helper
pnpm build
cargo check --release --manifest-path src-tauri/Cargo.toml

echo
echo "Release ${VERSION} prepared."
echo
echo "Review the changes with:"
echo "  git diff"
echo
echo "Then commit them before creating tag v${VERSION}."