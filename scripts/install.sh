#!/bin/sh
# Installs the kuukura CLI (`ku` and `kuukura`) on macOS or Linux.
#   curl -fsSL https://raw.githubusercontent.com/victorlunam/kuukura/main/scripts/install.sh | sh
# Environment:
#   KU_VERSION      a release such as 2026.10.2 (default: the latest release)
#   KU_INSTALL_DIR  where to put the programs (default: $HOME/.local/bin; no sudo is used)
# The archive is checked against the release's checksums.txt before anything is installed.
set -eu

repo="victorlunam/kuukura"
dir="${KU_INSTALL_DIR:-$HOME/.local/bin}"

die() { echo "install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) die "unsupported system '$(uname -s)'; on Windows use scripts/install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported architecture '$(uname -m)' (supported: amd64, arm64)" ;;
esac
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sum() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  die "sha256sum or shasum is required"
fi

version="${KU_VERSION:-}"
if [ -z "$version" ]; then
  # /releases/latest redirects to /releases/tag/vYEAR.MONTH.N
  url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" ||
    die "could not find the latest release"
  version="${url##*/v}"
fi
version="${version#v}"
case "$version" in
  [0-9][0-9][0-9][0-9].[0-9]*.[0-9]*) ;;
  *) die "'$version' is not a release version (expected YEAR.MONTH.N, for example 2026.10.2)" ;;
esac

file="kuukura_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/v$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading kuukura $version for $os/$arch"
curl -fsSL -o "$tmp/$file" "$base/$file" || die "could not download $base/$file"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "could not download checksums.txt"

want="$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "checksums.txt has no entry for $file"
[ "$(sum "$tmp/$file")" = "$want" ] || die "checksum mismatch for $file; nothing was installed"

tar -xzf "$tmp/$file" -C "$tmp" kuukura ku
mkdir -p "$dir"
for p in kuukura ku; do
  cp "$tmp/$p" "$dir/$p.new"
  chmod 755 "$dir/$p.new"
  mv -f "$dir/$p.new" "$dir/$p"
done

echo "Installed in $dir:"
"$dir/ku" --version
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac
