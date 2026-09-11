# Release architecture

## Development versus release

Development and production have different execution environments but should expose the same application behavior.

### Development

```text
pnpm / Vite
    |
Tauri dev process
    |
local Python virtual environment
```

Developer tools such as `uv`, Node.js, Cargo, and a `.venv` are allowed.

### Production

```text
native installer
    |
Tauri application
    |
bundled Python sidecar
```

No development toolchain may be required on the user's laptop.

## Build stages

A complete release will eventually perform these stages on each target platform:

1. create a clean Python environment from the locked dependency graph;
2. freeze the Python backend and bundled parsers into a sidecar executable;
3. run sidecar smoke tests;
4. build the React frontend;
5. compile the Rust/Tauri application;
6. bundle the sidecar into the Tauri package;
7. create platform-native installers;
8. sign/notarize where required;
9. publish checksums and release artifacts.

## Versioning

OUH has version information in Python project metadata, Cargo metadata, and Tauri configuration. The release process should keep these synchronized.

Parser versions are independent from the OUH version but should be pinned for each OUH release.

## CI and release jobs

Ordinary CI should validate source code without publishing artifacts.

Release workflows should be triggered intentionally and should have only the permissions required to create release artifacts.

Publishing credentials should use short-lived or platform-native mechanisms where possible.

## Platform trust

A technically valid executable is not necessarily deployment-ready.

Production release work must also consider Authenticode/code signing on Windows, Apple Developer ID signing and notarization on macOS, BAM endpoint protection and allow-listing, and checksums/signatures for distributed Linux packages.

## Release acceptance

A release candidate should be tested on machines that do not contain the development checkout or Python environment.

The core acceptance test is:

> Can a normal user install OUH, launch it, authenticate, discover parsers, select files, process them, export logs, and close the application without installing developer tooling?
