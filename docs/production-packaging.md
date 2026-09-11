# Production packaging

## Goal

A released OUH installer must run on a user's machine without requiring Python, uv, Node.js, pnpm, Cargo, or a development checkout.

## Target bundle

```text
Tauri desktop executable
        |
        +--> bundled Python sidecar
                  |
                  +--> pybis
                  +--> bam-masterdata
                  +--> bundled parser packages
```

The frontend assets are compiled by Vite and embedded into the Tauri application.

## Python sidecar

During development, Python is executed from the project's virtual environment.

For production, the Python backend will be frozen into a native executable, initially using PyInstaller.

The sidecar must include `openbis_upload_helper`, `pybis`, `bam-masterdata`, parser distributions, parser package metadata needed for entry-point discovery, and transitive Python dependencies.

A build is not considered successful until the standalone sidecar can perform parser discovery, authentication, destination queries, and one representative processing run.

## Tauri integration

Tauri will bundle the sidecar as an external binary and resolve the packaged path at runtime.

All Python commands should use one backend-launch abstraction so development and production do not diverge.

## Native builds

Native artifacts should be built on the target operating system:

- Windows build runner for Windows installers;
- macOS build runner for macOS bundles;
- Linux build runner for Linux packages.

The Python sidecar is platform-specific and must be frozen separately per target platform.

## Planned artifacts

Expected release artifacts are approximately:

- Windows: NSIS `.exe` installer, optionally MSI;
- macOS: signed/notarized `.app` and/or `.dmg`;
- Linux: AppImage and/or `.deb`.

## Production dependency policy

Release builds should consume locked and versioned dependencies.

Parser packages bundled with an OUH release form part of that OUH release's supported runtime and should have explicit versions.

A parser update therefore normally requires a new OUH release.
