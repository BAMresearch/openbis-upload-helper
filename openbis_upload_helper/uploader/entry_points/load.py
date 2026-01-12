import importlib.metadata


def get_entry_point_parsers() -> dict[str, dict]:
    """
    Get all parsers by loading their entry points as defined in the `bam.parsers` group of each individual parser package.

    Returns:
        dict[str, dict]: A dictionary whose keys are parser names and values are dictionaries containing parser
            metadata (e.g., name, description, parser_class).
    """
    parsers = {}
    for entry_point in importlib.metadata.entry_points(group="bam.parsers"):
        try:
            parsers[entry_point.name] = entry_point.load()
        except Exception as e:
            raise RuntimeError(f"Failed to load entry point '{entry_point.name}': {e}")
    return parsers
