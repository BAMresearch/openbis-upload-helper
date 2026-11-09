#!/usr/bin/env bash

set -euo pipefail

echo "Generating parser documentation..."

python scripts/generate_parser_docs.py

echo "Parser documentation generated successfully."