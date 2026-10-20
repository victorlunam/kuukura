#!/bin/sh
# Prints the Homebrew formula for a release: scripts/homebrew/render.sh <version> <checksums.txt>
# The version has no leading "v" (2026.10.2). Fails if checksums.txt lacks one of the four archives.
set -eu
version="${1:?usage: render.sh <version> <checksums.txt>}"
checksums="${2:?usage: render.sh <version> <checksums.txt>}"
here="$(dirname "$0")"

expr="s/@VERSION@/$version/g"
for t in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
  sha="$(awk -v f="kuukura_${version}_$t.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$checksums")"
  [ -n "$sha" ] || { echo "render: no checksum for kuukura_${version}_$t.tar.gz" >&2; exit 1; }
  upper="$(echo "$t" | tr '[:lower:]' '[:upper:]')"
  expr="$expr;s/@SHA_$upper@/$sha/g"
done
sed "$expr" "$here/kuukura.rb.tmpl"
