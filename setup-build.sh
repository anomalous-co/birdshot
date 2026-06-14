#!/usr/bin/env bash
# Fetch DuckDB + extension-ci-tools (pinned to the runtime's v1.5.3) and build
# the birdshot extension. The compiled loadable lands at:
#   build/release/extension/birdshot/birdshot.duckdb_extension
#
# Point the host at it:
#   export BIRDSHOT_EXTENSION_PATH="$(pwd)/build/release/extension/birdshot/birdshot.duckdb_extension"
#
# Prereqs: cmake, ninja (or make), a C++17 compiler, and OpenSSL. The DuckDB
# extension template uses vcpkg for OpenSSL; on macOS you can instead point CMake
# at Homebrew's OpenSSL: export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)".
set -euo pipefail
cd "$(dirname "$0")"

DUCKDB_TAG="${DUCKDB_TAG:-v1.5.3}"

if [ ! -d duckdb/.git ]; then
  echo "==> cloning duckdb@${DUCKDB_TAG}"
  rm -rf duckdb
  git clone --branch "${DUCKDB_TAG}" --depth 1 https://github.com/duckdb/duckdb
fi

if [ ! -d extension-ci-tools/.git ]; then
  echo "==> cloning extension-ci-tools"
  rm -rf extension-ci-tools
  git clone --depth 1 https://github.com/duckdb/extension-ci-tools
fi

echo "==> building (this compiles DuckDB from source the first time — slow)"
GEN="${GEN:-ninja}" make release

echo
echo "==> done. Set:"
echo "    export BIRDSHOT_EXTENSION_PATH=\"$(pwd)/build/release/extension/birdshot/birdshot.duckdb_extension\""
