# Local Tauri Development

This document describes how to run the **openBIS Upload Helper** locally in Tauri development mode.

The current application consists of:

```text
React + TypeScript + Vite
        |
        | Tauri invoke(...)
        v
Rust/Tauri
        |
        | stdin/stdout JSON
        v
Python backend
        |
        | pybis
        v
openBIS
```

The repository uses:

- React
- TypeScript
- Vite
- Tauri 2
- Rust
- Python >= 3.12
- `uv`
- `pybis`
- Pydantic
- `pnpm`

## 1. Linux prerequisites

On Ubuntu, install the Tauri system dependencies:

```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

## 2. Node.js and pnpm

A current Node.js LTS release is recommended.

Verify:

```bash
node --version
```

Verify `pnpm`:

```bash
pnpm --version
```

If `pnpm` is not installed and Corepack is available:

```bash
corepack enable
corepack prepare pnpm@latest --activate
```

## 3. Rust

Install Rust using `rustup` if necessary:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Reload the shell, then verify:

```bash
rustc --version
cargo --version
```

Use the stable toolchain:

```bash
rustup default stable
```

## 4. Python and uv

The project currently requires Python 3.12 or newer.

Verify:

```bash
python3 --version
```

Verify `uv`:

```bash
uv --version
```

If `uv` is not installed, follow the official `uv` installation method for the development machine.

The Tauri development login command currently starts the Python backend through `uv`, so `uv` must be available in the environment in which `pnpm tauri dev` is launched.

## 5. Clone and enter the repository

```bash
git clone https://github.com/JosePizarro3/openbis-upload-helper.git
cd openbis-upload-helper
```

## 6. Install JavaScript dependencies

```bash
pnpm install
```

The repository defines the following relevant npm scripts:

```text
dev    -> vite
build  -> tsc && vite build
tauri  -> tauri
```

## 7. Install Python dependencies

From the repository root, create a virtual environment:

```bash
uv venv
uv sync --all-extras
```

This installs the Python project and its dependencies, including:

- `bam-masterdata`
- `pybis`
- `pydantic`

and development dependencies such as PyInstaller and Ruff.

Verify the Python entry point:

```bash
uv run openbis-upload-helper hello
```

Expected output:

```json
{"message":"Hello from Python"}
```

## 8. Start the local openBIS test instance

The current development login is configured to use:

```text
https://local.openbis.ch/openbis
```

Start the local Docker instance before testing authentication:

```bash
cd ~/openbis-7-test
docker compose up -d
```

Check readiness:

```bash
curl -vk https://local.openbis.ch/openbis/webapp/eln-lims/version.txt
```

Then return to the application repository:

```bash
cd ~/openbis-upload-helper
```

Current local test credentials are:

```text
Username: admin
Password: test
```

These are only for the isolated development instance.

## 9. Test the Python login independently

Before involving Tauri, the Python backend can be tested directly:

```bash
echo '{
  "server_url": "https://local.openbis.ch/openbis",
  "username": "admin",
  "password": "test",
  "personal_access_token": ""
}' | uv run openbis-upload-helper login
```

Expected successful response:

```json
{"success":true,"username":"admin","error":null}
```

This is useful for distinguishing Python/pybis problems from Tauri/Rust/frontend problems.

## 10. Run Tauri development mode

From the repository root:

```bash
pnpm tauri dev
```

Tauri automatically runs the configured Vite development command.

The frontend development server is normally available at:

```text
http://localhost:1420
```

but normal testing should be done through the Tauri desktop window rather than by opening the Vite URL directly.

## 11. Login during development

Use:

```text
Server URL:
https://local.openbis.ch/openbis

Username:
admin

Password:
test

Personal Access Token:
leave empty
```

The current authentication path is:

```text
LoginPage.tsx
    |
    v
auth.ts
    |
    | invoke("login")
    v
src-tauri/src/lib.rs
    |
    | launches: uv run openbis-upload-helper login
    | sends credentials through stdin as JSON
    v
src/openbis_upload_helper/main.py
    |
    v
pybis
    |
    v
local openBIS
```

Passwords and PATs are sent to the Python child process through `stdin`, rather than being passed as command-line arguments.

## 12. Open developer tools

In the Tauri development window, use:

```text
Ctrl + Shift + I
```

or right-click and choose **Inspect Element**.

This opens the WebKitGTK developer tools on Linux and provides access to:

- DOM inspection
- CSS inspection
- JavaScript console
- network information

## 13. Stop Tauri development mode

In the terminal running:

```bash
pnpm tauri dev
```

press:

```text
Ctrl+C
```

This stops the Tauri development process and Vite development server.

It does **not** stop the Docker/openBIS instance.

## 14. Frontend-only development

To run only Vite:

```bash
pnpm dev
```

This can be useful for pure React/CSS work.

However, functionality that depends on:

```ts
invoke(...)
```

requires the Tauri runtime and therefore should be tested with:

```bash
pnpm tauri dev
```

## 15. Useful checks

Tauri:

```bash
pnpm tauri info
```

Rust:

```bash
rustc --version
cargo --version
```

Node/pnpm:

```bash
node --version
pnpm --version
```

Python/uv:

```bash
python3 --version
uv --version
```

Python dependencies:

```bash
uv sync
```

## 16. Common issues

### Snap VS Code / GLIBC error

Running Tauri from a Snap-installed VS Code integrated terminal may leak Snap library paths into the build/runtime environment and produce errors involving:

```text
/snap/core20/...
libpthread.so.0
GLIBC_PRIVATE
```

If that happens, run:

```bash
pnpm tauri dev
```

from a normal Ubuntu terminal outside the Snap VS Code environment.

### Stale Rust/Tauri build artifacts

If paths or Tauri configuration have recently changed and Cargo reports stale generated paths, clean the Rust build:

```bash
cd src-tauri
cargo clean
cd ..
```

Then retry:

```bash
pnpm tauri dev
```

If necessary, the generated target directory can be removed and rebuilt:

```bash
rm -rf src-tauri/target
pnpm tauri dev
```

### `uv` cannot be found from Rust

The development Rust backend currently launches `uv`.

Check:

```bash
which uv
uv --version
```

Run `pnpm tauri dev` from a shell where `uv` is available in `PATH`.

### Login fails but the UI is running

Test each layer independently.

First openBIS:

```bash
curl -vk https://local.openbis.ch/openbis/webapp/eln-lims/version.txt
```

Then Python:

```bash
echo '{
  "server_url": "https://local.openbis.ch/openbis",
  "username": "admin",
  "password": "test",
  "personal_access_token": ""
}' | uv run openbis-upload-helper login
```

If both work, investigate the Tauri/Rust invocation.

### Port 1420 is already in use

Check for an old Vite/Tauri process and stop it before starting another development session.

## 17. Typical development workflow

Terminal 1 — openBIS:

```bash
cd ~/openbis-7-test
docker compose up -d
docker compose ps
```

Terminal 2 — application:

```bash
cd ~/openbis-upload-helper
uv sync
pnpm install
pnpm tauri dev
```

For ordinary day-to-day work, `uv sync` and `pnpm install` do not need to be repeated unless dependencies changed.

When finished:

```text
Ctrl+C
```

in the Tauri terminal.

Optionally stop openBIS:

```bash
cd ~/openbis-7-test
docker compose stop
```

## 18. Current development vs packaged application

During development, Rust currently launches the Python backend using:

```text
uv run openbis-upload-helper login
```

This is intentionally a development mechanism.

The packaged desktop application will later use a Python executable bundled with PyInstaller and configured as a Tauri sidecar. End users should not need Python, `uv`, or the project source tree installed.
