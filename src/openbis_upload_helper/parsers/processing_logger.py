import sys

import structlog


def create_processing_logger():
    """
    Create a logger specifically for the desktop processing protocol.

    Every log record is written as one JSON object per stdout line so
    that the Tauri backend can consume the stream incrementally.
    """
    return structlog.wrap_logger(
        structlog.PrintLogger(
            file=sys.stdout,
        ),
        processors=[
            structlog.processors.TimeStamper(
                fmt="iso",
            ),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
