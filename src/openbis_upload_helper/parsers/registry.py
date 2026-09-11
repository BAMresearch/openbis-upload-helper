from dataclasses import dataclass
from importlib import metadata
from typing import Any

from bam_masterdata.parsing import AbstractParser
from pydantic import BaseModel, Field

ENTRY_POINT_GROUP = "bam.parsers"


@dataclass(frozen=True)
class ParserPlugin:
    id: str
    name: str
    description: str
    version: str | None
    parser_class: type[AbstractParser]


class ParserInfo(BaseModel):
    id: str
    name: str
    description: str = ""
    version: str | None = None


class ParsersResult(BaseModel):
    success: bool
    parsers: list[ParserInfo] = Field(default_factory=list)
    error: str | None = None


def _entry_point_version(entry_point: metadata.EntryPoint) -> str | None:
    distribution = getattr(entry_point, "dist", None)

    if distribution is None:
        return None

    return distribution.version


def discover_parsers() -> dict[str, ParserPlugin]:
    """
    Discover installed parser plugins registered under ``bam.parsers``.

    The entry-point name is used as the stable internal parser ID.
    The loaded entry point is expected to expose the metadata dictionary
    used by BAM parser packages, including ``name`` and ``parser_class``.
    """
    parsers: dict[str, ParserPlugin] = {}

    entry_points = metadata.entry_points(group=ENTRY_POINT_GROUP)

    for entry_point in entry_points:
        loaded: Any = entry_point.load()

        if not isinstance(loaded, dict):
            raise TypeError(
                f"Parser entry point '{entry_point.name}' must return a dictionary."
            )

        parser_class = loaded.get("parser_class")

        if parser_class is None:
            raise ValueError(
                f"Parser entry point '{entry_point.name}' does not define 'parser_class'."
            )

        parser_name = loaded.get("name", entry_point.name)
        description = loaded.get("description", "")

        parsers[entry_point.name] = ParserPlugin(
            id=entry_point.name,
            name=parser_name,
            description=description,
            version=_entry_point_version(entry_point),
            parser_class=parser_class,
        )

    return parsers


def get_parser(parser_id: str) -> ParserPlugin:
    parsers = discover_parsers()

    try:
        return parsers[parser_id]
    except KeyError as exc:
        raise ValueError(f"Unknown parser '{parser_id}'.") from exc


def list_parsers() -> ParsersResult:
    try:
        plugins = discover_parsers()

        parsers = [
            ParserInfo(
                id=plugin.id,
                name=plugin.name,
                description=plugin.description,
                version=plugin.version,
            )
            for plugin in plugins.values()
        ]

        parsers.sort(key=lambda parser: parser.name.lower())

        return ParsersResult(
            success=True,
            parsers=parsers,
        )

    except Exception as exc:
        return ParsersResult(
            success=False,
            error=f"Could not load parsers: {exc}",
        )
