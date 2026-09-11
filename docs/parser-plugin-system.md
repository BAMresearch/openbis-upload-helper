# Parser plugin system

## Purpose

OUH supports scientific parsers as Python plugins rather than hard-coding parser classes into the application.

This allows parser packages to evolve independently from the desktop UI.

## Discovery

Parser packages register entry points under the Python entry-point group:

```toml
[project.entry-points."bam.parsers"]
example_parser = "some_package:some_entry_point"
```

OUH discovers installed parsers using `importlib.metadata.entry_points(group="bam.parsers")`.

Each entry point loads a metadata dictionary containing at least a parser class and normally a display name and description.

## Parser identity

The entry-point name is the stable internal parser identifier.

For example:

```toml
[project.entry-points."bam.parsers"]
openbis_parser_example = "openbis_parser_example:openbis_parser_example_entry_point"
```

The user-facing name may be more descriptive than the stable ID.

The installed distribution version is obtained from the entry point's owning distribution and exposed to the frontend.

## Assignment model

Parser assignments are stored separately from the file-system tree.

An explicit assignment can be:

- a parser ID; or
- `Ignore`.

Assignments inherit down the source tree:

- a child inherits the nearest ancestor parser assignment;
- a child can override an inherited parser;
- `Ignore` stops parser inheritance;
- a descendant can explicitly assign a parser again.

This keeps `SourceNode` focused on file-system state.

## Processing jobs

Each explicit parser assignment creates a distinct processing job.

This matters because a parser may interpret a group of files collectively. Two directories explicitly assigned to the same parser are therefore still two separate jobs.

A job contains:

- parser ID;
- assignment path;
- concrete file paths.

Only concrete file paths are sent to Python.

## Production packaging

The first production release should bundle a known, fixed set of parser distributions with the Python sidecar.

Dynamic installation of arbitrary third-party parsers is intentionally deferred. A fixed parser set improves reproducibility, supportability, and security.

When a parser package is bundled into a frozen Python executable, its Python entry-point metadata must remain discoverable. The production build should include a parser-discovery smoke test.
