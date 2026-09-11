# Security model

## Principles

OUH should expose the smallest practical native surface to the frontend and keep sensitive state outside React.

The production application should assume that UI code is less trusted than the Rust boundary.

## Credentials

Authentication credentials are entered in the React login form and immediately sent through a Tauri command.

After successful authentication:

- the openBIS token is stored in Rust memory;
- React does not receive the token;
- the token is not written to processing logs;
- the token is not placed in command-line arguments.

The Python backend receives authentication data through standard input rather than CLI arguments.

## Session persistence

The initial production version may keep authentication session-only.

If persistent login is introduced later, credentials or tokens should use operating-system credential storage rather than plaintext configuration files.

## Native capabilities

Tauri capabilities should remain narrowly scoped.

Only features required by the application should be granted. New plugins or permissions should be reviewed rather than enabled globally.

## Content Security Policy

Development may temporarily use a relaxed or disabled CSP, but a production release should define an explicit restrictive Content Security Policy.

The packaged application should not require arbitrary remote scripts or remote frontend content.

## Local files

The application handles user-selected scientific files.

The source-scanning and processing layers should:

- avoid following symbolic links unexpectedly;
- validate paths immediately before processing;
- never execute selected scientific files;
- avoid broad writable access beyond operations explicitly requested by the user.

## Process isolation

Scientific parsers execute in the Python sidecar rather than inside the webview.

This provides a useful process boundary and allows Rust to supervise and terminate long-running processing.

A parser still runs with the current user's operating-system privileges, so bundled parser code must be treated as trusted application code.

## Logging

Logs should help diagnose processing without leaking secrets.

Do not include passwords, personal access tokens, authentication headers, or full credential payloads.

Exported diagnostic logs may contain file paths, destination identifiers, and parser messages and should therefore be treated as potentially sensitive operational data.

## Dependency and release security

Production releases should use reproducible locked dependencies, fixed parser versions, reviewed release workflows, code signing where applicable, and platform-native installer trust mechanisms.

Mutable Git branches should not be used as production dependencies.
