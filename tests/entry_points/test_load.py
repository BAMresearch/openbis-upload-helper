from types import SimpleNamespace
from unittest.mock import patch

from openbis_upload_helper.uploader.entry_points import get_entry_point_parsers


@patch("importlib.metadata.entry_points")
def test_get_entry_point_parsers(mock_entry_points):
    mock_entry_points.return_value = [
        SimpleNamespace(
            name="masterdata_parser_example_entry_point",
            load=lambda: {
                "name": "MasterdataParserExample",
                "description": "An example parser for masterdata.",
                "parser_class": object(),
            },
        ),
    ]
    parsers = get_entry_point_parsers()
    assert isinstance(parsers, dict)
    assert "masterdata_parser_example_entry_point" in parsers
    assert (
        parsers["masterdata_parser_example_entry_point"]["name"]
        == "MasterdataParserExample"
    )
    assert (
        parsers["masterdata_parser_example_entry_point"]["description"]
        == "An example parser for masterdata."
    )
    assert "parser_class" in parsers["masterdata_parser_example_entry_point"]
