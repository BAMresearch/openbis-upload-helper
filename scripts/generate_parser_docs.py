from pathlib import Path

from src.openbis_upload_helper.parsers.registry import list_parsers

OUTPUT = Path("AVAILABLE_PARSERS.md")


def generate_docs():
    result = list_parsers()

    if not result.success:
        raise RuntimeError(result.error)

    lines = [
        "# Available Parsers",
        "",
        "Automatically generated parser documentation.",
        "",
        "| ID | Name | Description | Version |",
        "| --- | --- | --- | --- |",
    ]

    for parser in result.parsers:
        description = parser.description.replace("\n", " ").replace("|", "\\|")

        lines.append(
            f"| `{parser.id}` "
            f"| {parser.name} "
            f"| {description} "
            f"| {parser.version or 'N/A'} |"
        )

    OUTPUT.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(f"Generated {OUTPUT}")


if __name__ == "__main__":
    generate_docs()
