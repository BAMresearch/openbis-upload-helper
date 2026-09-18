from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYPROJECT = ROOT / "pyproject.toml"
CARGO_TOML = ROOT / "src-tauri" / "Cargo.toml"
TAURI_CONFIG = ROOT / "src-tauri" / "tauri.conf.json"
PACKAGE_JSON = ROOT / "package.json"


VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def validate_version(version: str) -> None:
    if not VERSION_PATTERN.fullmatch(version):
        raise SystemExit(
            f"Invalid version '{version}'. Expected MAJOR.MINOR.PATCH, for example 1.0.1."
        )


def replace_first_version(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")

    updated, count = re.subn(
        r'(?m)^version = "\d+\.\d+\.\d+"$',
        f'version = "{version}"',
        text,
        count=1,
    )

    if count != 1:
        raise RuntimeError(
            f"Could not update exactly one version declaration in {path}"
        )

    path.write_text(updated, encoding="utf-8")


def update_json_version(path: Path, version: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))

    if "version" not in data:
        raise RuntimeError(f"No version field found in {path}")

    data["version"] = version

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: uv run python scripts/set_version.py MAJOR.MINOR.PATCH"
        )

    version = sys.argv[1]
    validate_version(version)

    replace_first_version(PYPROJECT, version)
    replace_first_version(CARGO_TOML, version)
    update_json_version(TAURI_CONFIG, version)
    update_json_version(PACKAGE_JSON, version)

    print(f"Version set to {version} in:")
    print(f"  {PYPROJECT.relative_to(ROOT)}")
    print(f"  {CARGO_TOML.relative_to(ROOT)}")
    print(f"  {TAURI_CONFIG.relative_to(ROOT)}")
    print(f"  {PACKAGE_JSON.relative_to(ROOT)}")
    print()
    print("Now run:")
    print("  uv lock")
    print("  cargo check --manifest-path src-tauri/Cargo.toml")
    print("  pnpm install --lockfile-only")


if __name__ == "__main__":
    main()
