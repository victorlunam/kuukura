#!/bin/sh
# Signs the macOS binaries of a release with your Developer ID and re-uploads them.
# Use it when the release was built without the MACOS_CERT_P12 secret. Needs: gh, codesign, the identity in your keychain.
#   scripts/sign-macos.sh vYEAR.MONTH.N
set -eu
tag="${1:?usage: scripts/sign-macos.sh <tag>}"
id="${KU_SIGN_ID:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:.*\)"/\1/p' | head -1)}"
[ -n "$id" ] || { echo "no Developer ID Application identity in the keychain" >&2; exit 1; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cd "$work"
gh release download "$tag" --repo victorlunam/kuukura --pattern 'kuukura_*_darwin_*.tar.gz' --pattern checksums.txt
for f in kuukura_*_darwin_*.tar.gz; do
  d="x_${f%.tar.gz}"; mkdir "$d"; tar -xzf "$f" -C "$d"
  codesign --force --options runtime --timestamp -s "$id" "$d/kuukura"
  cp "$d/kuukura" "$d/ku"
  codesign --verify --strict "$d/kuukura"
  tar -C "$d" -czf "$f" kuukura ku
done
grep -v '_darwin_' checksums.txt > c.new; shasum -a 256 kuukura_*_darwin_*.tar.gz >> c.new; mv c.new checksums.txt
gh release upload "$tag" --repo victorlunam/kuukura --clobber kuukura_*_darwin_*.tar.gz checksums.txt
echo "signed with: $id"
