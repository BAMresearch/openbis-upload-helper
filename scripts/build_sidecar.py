from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"
BINARIES_DIR = ROOT / "src-tauri" / "binaries"

BASE_NAME = "openbis-helper-python"


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
        "--collect-all",
        "openbis_parser_example",
        "--collect-all",
        "bruker_powderxrd_parser",
        "--copy-metadata",
        "bam-masterdata",
        "--copy-metadata",
        "openbis-parser-example",
        "--copy-metadata",
        "bruker-powderxrd-parser",
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


if __name__ == "__main__":
    main()
