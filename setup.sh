#!/usr/bin/env bash
# One-click setup for Bounty Mode (Linux / macOS).
#
#   ./setup.sh
#
# Installs the package, asks for your OpenRouter key and name, writes .env, and
# launches the UI.  Everything real happens in setup.py; this is a thin wrapper
# so the same command works on every platform.
set -euo pipefail

cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "Python 3.9+ is required but was not found on PATH." >&2
  exit 1
fi

exec "$PY" setup.py "$@"
