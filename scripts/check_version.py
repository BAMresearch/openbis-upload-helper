from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_JSON = ROOT / "package.json"
TAURI_CONFIG = ROOT / "src-tauri" / "tauri.conf.json"


def read_versions() -> dict[str, str]:
    with PYPROJECT.open("rb") as file:
        pyproject = tomllib.load(file)

    with PACKAGE_JSON.open(encoding="utf-8") as file:
        package_json = json.load(file)

    with TAURI_CONFIG.open(encoding="utf-8") as file:
        tauri_config = json.load(file)

    return {
        "pyproject.toml": pyproject["project"]["version"],
        "package.json": package_json["version"],
        "src-tauri/tauri.conf.json": tauri_config["version"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--tag",
        help="Release tag to verify, for example v1.2.0.",
    )

    args = parser.parse_args()

    versions = read_versions()

    authoritative_version = versions["pyproject.toml"]

    mismatches = {
        source: version
        for source, version in versions.items()
        if version != authoritative_version
    }

    if mismatches:
        details = ", ".join(
            f"{source}={version}" for source, version in versions.items()
        )

        raise RuntimeError(
            "Application versions are not synchronized. "
            f"Expected {authoritative_version} from pyproject.toml. "
            f"Found: {details}"
        )

    if args.tag is not None:
        expected_tag = f"v{authoritative_version}"

        if args.tag != expected_tag:
            raise RuntimeError(
                f"Release tag does not match application version. Expected {expected_tag}, got {args.tag}."
            )

    print(f"Application version verified: {authoritative_version}")


if __name__ == "__main__":
    main()
