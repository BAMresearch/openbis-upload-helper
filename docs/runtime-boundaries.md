# Runtime boundaries

## Overview

OUH has three runtime layers: React, Rust/Tauri, and Python. Keeping the boundaries explicit is important for security, maintainability, and production packaging.

## React to Rust

React calls Tauri commands using `invoke(...)`.

Typical commands include:

- login;
- list spaces;
- list projects;
- list collections;
- discover parsers;
- scan sources;
- process sources;
- cancel processing;
- save processing logs.

Command inputs are plain serializable data. React should not receive native process handles, Python objects, or openBIS client objects.

## Rust to Python

Rust starts the Python backend as a child process.

Requests are serialized as JSON and sent through standard input. Python returns JSON results through standard output.

Long-running processing uses JSON Lines so events can be emitted incrementally:

```json
{"kind":"stage","level":"info","event":"Connecting to openBIS.","stage":"openbis"}
{"kind":"log","level":"info","event":"Parsing finished."}
{"kind":"result","result":{"success":true,"processed_files":2,"jobs":1}}
```

This protocol avoids running a local HTTP service solely to connect the desktop shell to Python.

## Python to Rust to React events

During processing, Python emits structured log events. Rust reads them line by line and emits Tauri events such as `processing-event`.

React subscribes to these events and updates the UI without polling.

This supports:

- live logs;
- current-stage display;
- warning/error counters;
- log-level filtering;
- progress feedback;
- cancellation feedback.

## Authentication boundary

Credentials originate in React because the user types them there, but they are immediately passed to Rust and then to the Python authentication command.

After successful authentication:

- the Python backend returns an authentication token to Rust;
- Rust stores the server URL and token in memory;
- the token is not returned to React.

Subsequent authenticated commands retrieve the token from Rust state.

## File-system boundary

React does not directly walk arbitrary local paths. Native source scanning is handled by Rust.

Processing requests contain explicit file paths selected through the application. Before parsing, Python validates that paths:

- are absolute;
- still exist;
- are files;
- are not symbolic links.

## Production implication

Production packaging must preserve these boundaries. Replacing the development Python environment with a bundled sidecar must not change the React API or move credentials into the frontend.
