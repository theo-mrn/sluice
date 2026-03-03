#!/bin/sh
# Formats the C sources with clang-format, following .clang-format.
#
#   tools/format.sh          rewrites the files
#   tools/format.sh check    changes nothing; fails (and says where) if a file is not formatted
#
# Uses the clang-format of the PATH, or "uvx clang-format" when there is none. Different versions of
# clang-format can disagree on details: check with the version you formatted with.
set -eu
cd "$(dirname "$0")/.."

if command -v clang-format >/dev/null 2>&1; then
    fmt="clang-format"
elif command -v uvx >/dev/null 2>&1; then
    fmt="uvx clang-format"
else
    echo "format.sh: needs clang-format (or uvx, which can fetch it)" >&2
    exit 2
fi

files=$(find src tests fuzz \( -name '*.c' -o -name '*.h' \) | sort)

if [ "${1:-}" = "check" ]; then
    # shellcheck disable=SC2086
    exec $fmt --dry-run --Werror $files
fi
# shellcheck disable=SC2086
exec $fmt -i $files
