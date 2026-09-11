# openBIS Upload Helper documentation

This folder documents the architecture and engineering decisions behind the Tauri-based openBIS Upload Helper (OUH).

## Architecture

- [Architecture overview](architecture-overview.md) — high-level structure of React, Tauri/Rust, Python, parsers, and openBIS.
- [Runtime boundaries](runtime-boundaries.md) — responsibilities of each layer and how data crosses process boundaries.
- [Parser plugin system](parser-plugin-system.md) — parser discovery, assignment, and execution.
- [Processing workflow](processing-workflow.md) — source selection, parser assignment, processing, logging, cancellation, and upload behavior.
- [Security model](security-model.md) — credential handling, process isolation, file access, and hardening.
- [Production packaging](production-packaging.md) — target cross-platform packaging model.
- [Release architecture](release-architecture.md) — how Python sidecars, Tauri bundles, and platform-native installers fit together.

## Existing development documentation

- [Tauri local development](tauri-local-development.md)
- [Local openBIS with Docker](openbis-local-docker.md)

## Guiding principle

OUH is a desktop application, not a local web service. React provides the user interface, Rust/Tauri owns native capabilities and sensitive runtime state, and Python provides the scientific/openBIS integration layer.
