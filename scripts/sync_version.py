from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_JSON = ROOT / "package.json"
TAURI_CONFIG = ROOT / "src-tauri" / "tauri.conf.json"


def read_authoritative_version() -> str:
    with PYPROJECT.open("rb") as file:
        pyproject = tomllib.load(file)

    return pyproject["project"]["version"]


def update_json_version(
    path: Path,
    version: str,
) -> None:
    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    data["version"] = version

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def main() -> None:
    version = read_authoritative_version()

    update_json_version(PACKAGE_JSON, version)

    update_json_version(TAURI_CONFIG, version)

    print(f"Synchronized application version to {version}")


if __name__ == "__main__":
    main()
