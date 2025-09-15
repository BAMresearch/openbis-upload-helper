from openbis_upload_helper.uploader.entry_points import get_entry_point_parsers


def test_get_entry_point_parsers():
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
