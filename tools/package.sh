#!/bin/sh
# Packs a built binary with what goes beside it: sh tools/package.sh VERSION PLATFORM BINARY
# -> out/sluice-VERSION-PLATFORM.tar.gz, holding sluice-VERSION-PLATFORM/ with the binary, the licences, the
# documents, the example policies and the webhook command. A smoke test runs the packed binary first.
set -eu

version=$1
platform=$2
binary=$3
name=sluice-$version-$platform
here=$(cd "$(dirname "$0")/.." && pwd)

"$binary" --version
"$binary" --test-policy "$here/examples/policies/agent-readonly.toml" "$here/examples/policies/agent-readonly.tests"

rm -rf "out/$name" && mkdir -p "out/$name/share"
cp "$binary" "out/$name/sluice"
cp "$here/LICENSE" "$here/THIRD_PARTY_NOTICES.md" "$here/CHANGELOG.md" "$here/README.md" "$here/SECURITY.md" "out/$name/"
cp -R "$here/docs" "out/$name/docs"
cp -R "$here/examples" "out/$name/examples"
cp "$here/tools/webhook.sh" "out/$name/share/webhook.sh"
tar -C out -czf "out/$name.tar.gz" "$name"
echo "out/$name.tar.gz"
