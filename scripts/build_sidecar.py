from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIST_DIR = ROOT / "dist"
BINARIES_DIR = ROOT / "src-tauri" / "binaries"

BASE_NAME = "openbis-helper-python"

PARSER_ENTRY_POINT_GROUP = "bam.parsers"


def tauri_target_triple() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in {"x86_64", "amd64"}:
            return "x86_64-unknown-linux-gnu"

        if machine in {"aarch64", "arm64"}:
            return "aarch64-unknown-linux-gnu"

    if system == "windows":
        if machine in {"x86_64", "amd64"}:
            return "x86_64-pc-windows-msvc"

        if machine in {"aarch64", "arm64"}:
            return "aarch64-pc-windows-msvc"

    if system == "darwin":
        if machine in {"x86_64", "amd64"}:
            return "x86_64-apple-darwin"

        if machine in {"aarch64", "arm64"}:
            return "aarch64-apple-darwin"

    raise RuntimeError(f"Unsupported platform: {system} / {machine}")


def parser_build_arguments() -> list[str]:
    arguments: list[str] = []
    seen: set[tuple[str, str]] = set()

    entry_points = metadata.entry_points(
        group=PARSER_ENTRY_POINT_GROUP,
    )

    for entry_point in entry_points:
        distribution = entry_point.dist

        if distribution is None:
            raise RuntimeError(
                f"Parser entry point '{entry_point.name}' "
                "does not belong to a distribution."
            )

        module_name = entry_point.value.split(":", maxsplit=1)[0].split(
            ".", maxsplit=1
        )[0]

        package = (module_name, distribution.name)

        if package in seen:
            continue

        seen.add(package)

        arguments.extend(
            [
                "--collect-all",
                module_name,
                "--copy-metadata",
                distribution.name,
            ]
        )

    return arguments


def expected_parser_ids() -> set[str]:
    return {
        entry_point.name
        for entry_point in metadata.entry_points(group=PARSER_ENTRY_POINT_GROUP)
    }


def verify_sidecar_parsers(executable: Path) -> None:
    result = subprocess.run(
        [str(executable), "parsers"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)

    if not payload.get("success"):
        raise RuntimeError(
            f"Frozen sidecar could not discover parsers: {payload.get('error')}"
        )

    packaged_parser_ids = {parser["id"] for parser in payload.get("parsers", [])}

    expected = expected_parser_ids()

    if packaged_parser_ids != expected:
        missing = expected - packaged_parser_ids
        unexpected = packaged_parser_ids - expected

        raise RuntimeError(
            "Frozen sidecar parser discovery does not "
            "match the build environment. "
            f"Missing: {sorted(missing)}. "
            f"Unexpected: {sorted(unexpected)}."
        )

    print(f"Frozen sidecar parser discovery verified: {sorted(packaged_parser_ids)}")


def main() -> None:
    target = tauri_target_triple()

    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        BASE_NAME,
        "--collect-all",
        "bam_masterdata",
        "--copy-metadata",
        "bam-masterdata",
        "--collect-data",
        "pySPM",
        *parser_build_arguments(),
        str(ROOT / "src" / "openbis_upload_helper" / "main.py"),
    ]

    print(f"Building Python sidecar for {target}")

    subprocess.run(command, cwd=ROOT, check=True)

    suffix = ".exe" if platform.system() == "Windows" else ""

    source = DIST_DIR / f"{BASE_NAME}{suffix}"

    destination = BINARIES_DIR / f"{BASE_NAME}-{target}{suffix}"

    if not source.exists():
        raise RuntimeError(f"Expected PyInstaller output was not found: {source}")

    shutil.copy2(source, destination)

    print(f"Sidecar staged at {destination}")

    verify_sidecar_parsers(destination)


if __name__ == "__main__":
    main()
