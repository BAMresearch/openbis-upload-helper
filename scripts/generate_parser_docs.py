from pathlib import Path
import textwrap
from openbis_upload_helper.parsers.registry import list_parsers

OUTPUT = Path("available_parsers.md")


def generate_docs():
    result = list_parsers()

    if not result.success:
        raise RuntimeError(result.error)

    lines = [
        "# Available Parsers",
        "",
        "Automatically generated parser documentation.",
        "",
        "| Name | Description | Version |",
        "| --- | --- | --- |",
    ]

    for parser in result.parsers:
        description = "<br>".join(
            textwrap.wrap(
                parser.description.replace("\n", " "),
                width=60,   # Limit the width of the description to 60 characters
                break_long_words=False,
                break_on_hyphens=False,
            )
        ).replace("|", "\\|")

        lines.append(
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
