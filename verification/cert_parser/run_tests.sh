# Licensed under the Apache-2.0 license

#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Get the directory of the script to run commands from the correct location.
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Setting up Python environment..."
cd "$SCRIPT_DIR"
uv venv --clear
uv pip install -e . --index-url https://pypi.org/simple

echo "Running tests..."
.venv/bin/pytest

echo "Test run complete."
