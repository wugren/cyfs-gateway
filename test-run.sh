#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to run tests from this shortcut."
  echo "Install uv from: https://docs.astral.sh/uv/getting-started/installation/"
  exit 1
fi

export UV_PROJECT_ENVIRONMENT=".venv"
export UV_CACHE_DIR="$ROOT_DIR/.harness/uv-cache"
mkdir -p "$UV_CACHE_DIR"
VENV_PYTHON=".venv/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
  echo "Creating local Python virtual environment in .venv"
  uv venv .venv
fi

# Activation scripts are sourced code and may read shell-specific variables
# such as OSTYPE without a default. Suspend nounset only while sourcing them.
set +u
. ".venv/bin/activate"
set -u

if [ -f "pyproject.toml" ]; then
  echo "Syncing Python environment with uv"
  uv sync
elif [ -f "requirements.txt" ]; then
  echo "Installing requirements into .venv with uv"
  uv pip install --python "$VENV_PYTHON" -r requirements.txt
fi

if [ "$#" -eq 0 ]; then
  set -- all all
fi

exec uv run --active python "harness/scripts/test-run.py" "$@"
