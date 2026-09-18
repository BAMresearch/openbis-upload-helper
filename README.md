# openBIS Upload Helper

The **openBIS Upload Helper** is a desktop application for preparing and uploading scientific data to openBIS.

It helps users:

- choose files or folders to upload,
- select the target openBIS space/project/collection,
- run format-specific parsers,
- extract metadata from scientific data,
- create the corresponding objects and datasets in openBIS.

The application is built with **Tauri**, **React/TypeScript**, **Rust**, and a bundled **Python sidecar**.

## Installation

Pre-built desktop packages are provided through GitHub Releases.

Supported packages:

- **Windows**: NSIS `.exe` installer
- **Linux**: `.AppImage`
- **macOS**: `.dmg` / `.app`

Production users do not need Python, Node.js, Rust, uv, or pnpm installed.

On Windows, the installer uses a per-user installation and does not require administrator credentials.

## How parsers work

Scientific file formats and workflows are handled through dedicated **parser plugins**.

A parser knows how to interpret a specific file or folder structure and can:

- extract relevant metadata,
- map metadata to the BAM data model,
- create the required openBIS objects,
- upload associated files as datasets.

Parsers are discovered through Python entry points and are bundled into each application release.

The current production application therefore ships with a fixed parser set. Users do not install parsers separately.

If support for a new format or workflow is needed, please open a GitHub issue describing:

- the file format or folder structure,
- the metadata that should be extracted,
- the expected openBIS representation,
- example files where possible.

A new parser can then be developed and included in a future release.

## Data model

The application uses [`bam-masterdata`](https://github.com/BAMresearch/bam-masterdata) as the common data model for creating objects and metadata in openBIS.

This keeps parser outputs aligned with the BAM-wide schema instead of defining independent object structures for each parser.

## Authentication

The application connects directly to openBIS.

Authentication can use:

- username/password,
- personal access token (PAT).

Credentials and tokens are session-only and are not stored persistently by the application.

## Development

Developer setup, local development, sidecar builds, CI, packaging, versioning, and release procedures are documented in:

[`INSTRUCTIONS.md`](INSTRUCTIONS.md)

For local development, the main command is:

```bash
pnpm tauri dev
```

See `INSTRUCTIONS.md` for the full prerequisite and setup process.

## Issues and feedback

Please use GitHub Issues for:

- bug reports,
- usability feedback,
- feature requests,
- parser requests,
- installation or packaging problems.

When reporting a parser request, include representative example data whenever possible.
