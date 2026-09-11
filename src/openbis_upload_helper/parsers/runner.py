from pathlib import Path
from typing import Any

from bam_masterdata.cli.run_parser import RunParsers
from bam_masterdata.parsing import AbstractParser
from pydantic import BaseModel, Field

from openbis_upload_helper.client.openbis import (
    AuthRequest,
    get_authenticated_openbis,
)
from openbis_upload_helper.parsers.registry import discover_parsers


class ParserJobRequest(BaseModel):
    parser_id: str
    assignment_path: str
    paths: list[str] = Field(
        default_factory=list,
    )


class ProcessRequest(AuthRequest):
    space: str
    project: str
    collection: str = ""

    jobs: list[ParserJobRequest] = Field(
        default_factory=list,
    )


class ProcessResult(BaseModel):
    success: bool
    processed_files: int = 0
    jobs: int = 0
    error: str | None = None


def validate_file_path(
    raw_path: str,
) -> str:
    path = Path(raw_path)

    if not path.is_absolute():
        raise ValueError(f"Source path must be absolute: {raw_path}")

    if not path.exists():
        raise ValueError(f"Source file no longer exists: {raw_path}")

    if path.is_symlink():
        raise ValueError(f"Symbolic links are not supported: {raw_path}")

    if not path.is_file():
        raise ValueError(f"Source path is not a file: {raw_path}")

    return str(path)


def build_files_parser(
    jobs: list[ParserJobRequest],
) -> dict[AbstractParser, list[str]]:
    """
    Convert processing jobs into the structure expected
    by RunParsers.

    A fresh parser instance is created for every job,
    preserving explicit assignment boundaries.
    """
    available_parsers = discover_parsers()

    files_parser: dict[
        AbstractParser,
        list[str],
    ] = {}

    seen_paths: set[str] = set()

    for job in jobs:
        if not job.paths:
            continue

        plugin = available_parsers.get(
            job.parser_id,
        )

        if plugin is None:
            raise ValueError(f"Unknown parser '{job.parser_id}'.")

        validated_paths: list[str] = []

        for raw_path in job.paths:
            path = validate_file_path(
                raw_path,
            )

            if path in seen_paths:
                raise ValueError(
                    f"The same source file was assigned to multiple parser jobs: {path}"
                )

            seen_paths.add(path)
            validated_paths.append(path)

        if validated_paths:
            parser = plugin.parser_class()

            files_parser[parser] = validated_paths

    if not files_parser:
        raise ValueError("No parser jobs containing files were provided.")

    return files_parser


def run_parsers(
    request: ProcessRequest,
    logger: Any,
) -> ProcessResult:
    """
    Execute one processing operation.

    The supplied logger writes JSONL events to stdout.
    The complete operation remains inside one isolated
    Python process.
    """
    try:
        logger.info(
            "Validating processing plan.",
            kind="stage",
            stage="validation",
        )

        files_parser = build_files_parser(
            request.jobs,
        )

        processed_files = sum(len(paths) for paths in files_parser.values())

        logger.info(
            "Processing plan validated.",
            kind="stage",
            stage="validation",
            files=processed_files,
            jobs=len(files_parser),
        )

        logger.info(
            "Connecting to openBIS.",
            kind="stage",
            stage="openbis",
        )

        openbis = get_authenticated_openbis(
            request,
        )

        logger.info(
            "Initializing processing.",
            kind="stage",
            stage="initialization",
        )

        runner = RunParsers(
            openbis=openbis,
            space_name=request.space,
            project_name=request.project,
            collection_name=request.collection,
            files_parser=files_parser,
            logger=logger,
        )

        logger.info(
            "Running parsers and writing data to openBIS.",
            kind="stage",
            stage="processing",
        )

        runner.run()

        logger.info(
            "Processing completed.",
            kind="stage",
            stage="completed",
            files=processed_files,
            jobs=len(files_parser),
        )

        return ProcessResult(
            success=True,
            processed_files=processed_files,
            jobs=len(files_parser),
        )

    except Exception as exc:
        logger.error(
            "Processing failed.",
            kind="stage",
            stage="failed",
            error=str(exc),
        )

        return ProcessResult(
            success=False,
            error=f"Processing failed: {exc}",
        )
