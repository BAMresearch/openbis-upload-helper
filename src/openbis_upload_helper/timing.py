import os
import sys


def log_timing(message: str) -> None:
    if os.environ.get("OUH_TIMING") != "1":
        return

    print(f"[timing] {message}", file=sys.stderr, flush=True)
