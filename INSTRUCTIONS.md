# openBIS Upload Helper — Development, Build and Release Instructions

This document describes how to develop, validate, build and release the desktop
openBIS Upload Helper.

The production application consists of:

- a React/TypeScript frontend,
- a Tauri/Rust desktop backend,
- a bundled Python sidecar,
- the fixed parser dependencies shipped with the application.

Production users do **not** need Python, uv, Node.js, pnpm or Rust installed.

---

## 1. Repository structure

Relevant production files include:

```text
.github/workflows/
    ci.yml
    build-desktop.yml

scripts/
    build_sidecar.py
    set_version.py
    prepare_release.sh

src/
    openbis_upload_helper/

src-tauri/
    binaries/
    src/
    Cargo.toml
    tauri.conf.json

package.json
pnpm-lock.yaml
pyproject.toml
uv.lock
```

Generated sidecar binaries under `src-tauri/binaries/` are not committed.

---

## 2. Development prerequisites

Local development requires:

- Python 3.14
- uv
- Node.js
- pnpm
- Rust / Cargo
- Tauri operating-system prerequisites

Install the project dependencies with:

```bash
uv sync --locked
pnpm install --frozen-lockfile
```

On Linux, Tauri additionally requires the relevant WebKit/system development
packages.

---

## 3. Run the application in development

Run:

```bash
pnpm tauri dev
```

In development mode, Tauri starts the frontend and uses the local Python
environment rather than the packaged production sidecar.

The development machine therefore needs the Python dependencies installed with
`uv sync`.

---

## 4. Normal validation

Before merging normal development changes, the important local checks are:

```bash
uv run ruff check .
uv run python -m compileall src/openbis_upload_helper
pnpm build
cargo check --manifest-path src-tauri/Cargo.toml
cargo check --release --manifest-path src-tauri/Cargo.toml
```

The normal GitHub Actions workflow performs equivalent checks automatically on
pull requests and on pushes to `main`.

The normal CI intentionally does **not** build desktop installers.

---

## 5. Python production sidecar

The production application embeds the Python backend as a standalone executable.

Build it with:

```bash
uv run python scripts/build_sidecar.py
```

The script:

1. detects the current operating system and architecture,
2. invokes PyInstaller,
3. bundles the required Python packages and parser metadata,
4. writes the result using the target-triple filename expected by Tauri.

Typical outputs are:

```text
Linux:
src-tauri/binaries/openbis-helper-python-x86_64-unknown-linux-gnu

Windows:
src-tauri/binaries/openbis-helper-python-x86_64-pc-windows-msvc.exe

macOS:
src-tauri/binaries/openbis-helper-python-<architecture>-apple-darwin
```

PyInstaller builds are native. A Windows sidecar must be built on Windows, a
macOS sidecar on macOS, etc.

For official builds this is handled automatically by GitHub Actions.

Do not commit generated sidecar binaries.

---

## 6. Desktop production packages

Official desktop packages are built by:

```text
.github/workflows/build-desktop.yml
```

The workflow uses native GitHub-hosted runners for each operating system.

It produces:

### Windows

NSIS current-user installer:

```text
*.exe
```

The installer is configured for per-user installation and does not require
administrator credentials.

### Linux

AppImage:

```text
*.AppImage
```

No installation is necessary. Make the file executable if required and run it
directly.

### macOS

Application bundle and disk image:

```text
*.app
*.dmg
```

macOS is currently a secondary target for this project.

---

## 7. Manual desktop build

The desktop build workflow can also be started manually from GitHub:

```text
GitHub
→ Actions
→ Build desktop packages
→ Run workflow
```

The workflow builds the Python sidecar and desktop application independently on
Windows, Linux and macOS.

The resulting packages are available as GitHub Actions artifacts.

These build artifacts are temporary CI outputs. Official distributable versions
should be attached to a GitHub Release.

---

## 8. Versioning

The project uses Semantic Versioning:

```text
MAJOR.MINOR.PATCH
```

Examples:

```text
1.0.1   bug-fix release
1.1.0   backwards-compatible feature release
2.0.0   incompatible major release
```

The version must remain synchronized in:

```text
pyproject.toml
src-tauri/Cargo.toml
src-tauri/tauri.conf.json
package.json
```

Do not manually update only one of these files.

Use the release preparation script instead.

---

## 9. Prepare a release

From a clean development branch, run:

```bash
./scripts/prepare_release.sh X.Y.Z
```

For example:

```bash
./scripts/prepare_release.sh 1.0.1
```

The script:

1. updates the version in all four version declarations,
2. refreshes `uv.lock`,
3. refreshes `Cargo.lock`,
4. refreshes `pnpm-lock.yaml`,
5. runs Python lint/compile checks,
6. builds the frontend,
7. performs a Rust release check.

After it completes, inspect the changes:

```bash
git status
git diff
```

Do not create the release tag yet.

Commit the prepared release normally:

```bash
git add .
git commit -m "Prepare release 1.0.1"
git push
```

Create a pull request and allow the normal CI to pass.

Merge the release preparation into `main`.

---

## 10. Create the release tag

Only after the release-version commit has reached `main`, update the local
branch:

```bash
git checkout main
git pull
```

Then create the release tag:

```bash
git tag v1.0.1
git push origin v1.0.1
```

The tag must match the application version:

```text
Git tag:              v1.0.1
pyproject.toml:        1.0.1
Cargo.toml:            1.0.1
tauri.conf.json:       1.0.1
package.json:          1.0.1
```

Pushing a tag matching:

```text
v*
```

automatically starts the native desktop package workflow.

---

## 11. Validate release builds

Open the triggered GitHub Actions run and check all native jobs.

Expected jobs:

```text
Windows x64
Linux x64
macOS
```

All required jobs should succeed before publishing the release.

Download the generated artifacts.

For production-relevant releases, at minimum test:

### Windows

- installer opens,
- installation works without administrator credentials,
- application launches,
- openBIS login works,
- destination loading works,
- source selection works,
- parser assignment works,
- processing/upload works,
- cancellation works,
- log export works.

### Linux

- AppImage launches,
- bundled Python backend works,
- normal openBIS workflow works.

macOS currently only requires successful native build unless macOS becomes an
actively supported BAM target.

---

## 12. Publish the GitHub Release

After validating the build artifacts:

```text
GitHub
→ Releases
→ Draft a new release
```

Select the **existing** tag, for example:

```text
v1.0.1
```

Do not create a second tag.

Attach the platform packages generated by GitHub Actions:

```text
Windows:
*.exe

Linux:
*.AppImage

macOS:
*.dmg
```

The `.app` artifact may also be retained if useful, but the `.dmg` is the normal
macOS distribution artifact.

Add concise release notes describing:

- important fixes,
- new functionality,
- known issues,
- any migration or installation considerations.

Then publish the Release.

---

## 13. Updating an existing installation

There is currently no automatic updater.

### Windows

Users download the new NSIS installer and run it.

The new version upgrades/replaces the existing per-user installation. Users do
not normally need to uninstall the previous version first.

### Linux

AppImage is not installed in the traditional sense.

Users download the new AppImage and replace/delete the previous AppImage file.

### macOS

Users replace the previous application with the newer version distributed in the
new DMG.

---

## 14. Code signing and antivirus warnings

The current application is not code-signed.

As a result, Windows antivirus, SmartScreen or similar workstation security
software may warn the user before installation.

The application has been successfully installed and run on a BAM-managed Windows
workstation using the current-user installer.

If BAM later requires warning-free or centrally managed deployment, code signing
or organizational allow-listing should be handled with BAM IT.

Do not bypass managed workstation security controls.

---

## 15. Authentication and production security

Authentication is session-only.

Do not add credential persistence without an explicit security/design decision.

In production:

- passwords and PATs must not be passed through command-line arguments,
- session tokens must not be written to persistent storage,
- authentication values must not appear in logs,
- exported logs must remain sanitized,
- production errors should not expose raw backend tracebacks as normal
  user-facing messages.

---

## 16. Parser dependencies

The v1 application ships a fixed parser dependency set.

Parser plugins are discovered through Python entry points.

Adding or updating a parser therefore requires:

1. changing the relevant dependency in `pyproject.toml`,
2. refreshing `uv.lock`,
3. ensuring `scripts/build_sidecar.py` collects any package/metadata needed by
   PyInstaller,
4. rebuilding and validating the frozen Python sidecar,
5. producing new desktop packages.

Runtime installation of arbitrary parser plugins is intentionally not part of
v1.

---

## 17. Rebuilding after production changes

If production code or dependencies change:

```bash
uv sync --locked
pnpm install --frozen-lockfile
```

Run the normal validation:

```bash
uv run ruff check .
uv run python -m compileall src/openbis_upload_helper
pnpm build
cargo check --manifest-path src-tauri/Cargo.toml
cargo check --release --manifest-path src-tauri/Cargo.toml
```

For a local sidecar test:

```bash
uv run python scripts/build_sidecar.py
```

Official Windows/Linux/macOS packages should normally be produced through GitHub
Actions rather than manually.

---

## 18. Release checklist

Before publishing a release:

```text
[ ] Required changes merged
[ ] Version selected
[ ] prepare_release.sh completed
[ ] Version declarations synchronized
[ ] Lockfiles refreshed
[ ] Normal CI green
[ ] Release preparation merged to main
[ ] vX.Y.Z tag created from main
[ ] Desktop build workflow green
[ ] Windows package validated
[ ] Linux package validated
[ ] macOS build successful
[ ] Release notes prepared
[ ] Correct artifacts attached to GitHub Release
[ ] GitHub Release published
```