# Architecture overview

## Purpose

The openBIS Upload Helper (OUH) is a cross-platform desktop application for selecting local scientific files, assigning parsers, transforming those files into BAM masterdata objects, and writing the result to openBIS.

The application intentionally separates desktop UI concerns from scientific parsing and openBIS integration.

## High-level architecture

```text
React / TypeScript
        |
        | Tauri invoke + events
        v
Tauri / Rust
        |
        | JSON over stdin/stdout
        v
Python backend
        |
        +--> parser plugins
        |
        +--> bam-masterdata
        |
        +--> pybis
        |
        v
      openBIS
```

## React / TypeScript

React is responsible for presentation and interaction:

- login form and loading states;
- destination selection;
- local-source presentation;
- parser assignment;
- processing-plan review;
- streamed processing logs;
- log filtering and export;
- progress/cancellation controls.

React does not directly authenticate against openBIS and does not retain the openBIS token after login.

## Tauri / Rust

Tauri is the native desktop boundary. Rust is responsible for:

- exposing a constrained command API to React;
- keeping authentication state in native memory;
- scanning local files and directories;
- starting and supervising the Python backend;
- streaming backend log events to React;
- cancelling long-running processing;
- writing exported log files;
- enforcing that only one processing operation runs at a time.

Tauri replaces the old web-server-style architecture. OUH does not require Django, Redis, Celery, or a locally running HTTP backend.

## Python backend

Python remains the scientific and openBIS integration layer because the existing BAM tooling is Python-based. It is responsible for:

- authentication through `pybis`;
- querying openBIS spaces, projects, and collections;
- discovering parser plugins through Python entry points;
- constructing and running `bam-masterdata` processing;
- emitting structured processing events.

For development, Python is executed from the project virtual environment. For production, the Python backend is intended to be frozen into a platform-specific sidecar executable and bundled with the Tauri application.

## Why this split

The split lets each technology handle the part it is best suited for:

- React: interactive UI;
- Rust/Tauri: native desktop integration, process control, and sensitive state;
- Python: scientific ecosystem, parser plugins, `pybis`, and `bam-masterdata`.

The architecture also reduces coupling. Parser development can continue in Python without requiring parser authors to understand React or Rust.
