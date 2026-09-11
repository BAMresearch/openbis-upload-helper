# Processing workflow

## 1. Authentication

The user authenticates against an openBIS server using username/password or a personal access token.

Rust stores the resulting authentication token in memory.

## 2. Destination selection

The user selects an existing openBIS space and chooses or enters a project.

A collection is optional. If no collection is specified, generated objects are attached directly to the project where supported.

Missing projects or collections are created only when processing starts.

## 3. Source selection

Users add local files or directories.

Rust scans directories and returns a file tree to React. Symbolic-link traversal is deliberately avoided.

The source tree can be refreshed if local files change.

## 4. Parser assignment

Users explicitly assign parser plugins to source nodes.

Assignments inherit to descendants, can be overridden, and can be interrupted with `Ignore`.

The frontend resolves these assignments into a processing plan before calling the backend.

## 5. Processing plan

The plan contains independent parser jobs.

```text
ProcessingPlan
  jobs[]
    parserId
    assignmentPath
    paths[]
  ignoredPaths[]
  unassignedPaths[]
```

A processing plan is ready only when at least one file is assigned and no source remains unintentionally unassigned.

## 6. Python processing

Rust starts the Python backend and sends the authenticated destination and parser jobs as JSON.

Python:

1. validates paths;
2. resolves parser IDs;
3. instantiates one parser per processing job;
4. initializes `bam-masterdata` processing;
5. executes the parsers;
6. writes resulting objects, datasets, and relationships to openBIS.

## 7. Live logging

Processing emits JSONL events with level, message, timestamp, and optional stage metadata.

React displays these live and supports filters for Info, Warning, Error, and Debug. Debug messages are hidden by default but remain collected.

Exported JSON contains the complete event list, regardless of the active UI filter.

## 8. Cancellation

Rust owns the running Python child process during processing. A user cancellation terminates that child process.

Cancellation is not transactional. Data already written to openBIS before the cancellation may remain there.

The UI must therefore distinguish success, failure, and user cancellation.

## 9. Completion

A final structured result communicates whether processing succeeded and how many files/jobs were handled.

Future `bam-masterdata` versions may expose richer structured statistics. OUH should prefer structured result data over inferring such statistics from log text.
