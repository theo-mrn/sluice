#!/bin/sh
# Builds the static Linux binary, inside an Alpine container (musl): the one the releases and the container images are
# made of. It runs where `docker run` can mount the repository, from the root of the repository:
#
#   docker run --rm -v "$PWD":/src -w /src alpine:3.22 sh tools/build-static.sh [COMMIT]
#
# The result is dist/sluice (stripped), after the tests have passed on that very binary. Needs nothing on the host
# but Docker. COMMIT is what `sluice --version` says (default: unknown; the container has no git history to ask).
set -eu

commit=${1:-unknown}
apk add --no-cache gcc g++ musl-dev meson samurai pkgconf openssl-dev openssl-libs-static python3 openssl procps \
    linux-headers file binutils >/dev/null

# the repository is mounted read-only or owned by somebody else: build in a copy
rm -rf /work && mkdir /work
tar --exclude=./build --exclude=./build-asan --exclude=./dist -cf - . | tar -xf - -C /work
cd /work

meson setup build --buildtype=release -Db_ndebug=true -Dstatic=true -Dcommit="$commit" >/dev/null
meson compile -C build sluice
strip build/sluice
meson test -C build --print-errorlogs
file build/sluice
./build/sluice --version

mkdir -p /src/dist
cp build/sluice /src/dist/sluice
