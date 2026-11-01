#!/bin/sh
# Install the yunmen CLI from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/txchen/yunmen/master/scripts/install.sh | sh
#
# Environment:
#   YUNMEN_VERSION      release tag to install (default: latest)
#   YUNMEN_INSTALL_DIR  target directory (default: /usr/local/bin if writable, else ~/.local/bin)
#   YUNMEN_DOWNLOAD_BASE  override the release download URL (testing)
set -eu

REPO=txchen/yunmen

say() { printf '%s\n' "$*" >&2; }
die() { say "yunmen install: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "requires $1"; }
need curl
need tar
need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); Linux and macOS are supported" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m); amd64 and arm64 are supported" ;;
esac

version=${YUNMEN_VERSION:-}
if [ -z "$version" ]; then
  # The latest-release redirect avoids the rate-limited API.
  url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || die "cannot reach GitHub"
  version=${url##*/}
  case "$version" in v*) ;; *) die "no published release found" ;; esac
fi

base=${YUNMEN_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$version}
name="yunmen_${version}_${os}_${arch}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading yunmen $version for $os/$arch"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || die "download failed: $base/$name.tar.gz"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "download failed: $base/checksums.txt"

expected=$(grep " $name.tar.gz\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$expected" ] || die "no checksum listed for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  die "requires sha256sum or shasum to verify the download"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $name.tar.gz"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

dir=${YUNMEN_INSTALL_DIR:-}
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir=$HOME/.local/bin; fi
fi
mkdir -p "$dir"
install_tmp="$dir/.yunmen.$$"
cp "$tmp/$name/yunmen" "$install_tmp"
chmod 755 "$install_tmp"
mv -f "$install_tmp" "$dir/yunmen"

say "Installed $("$dir/yunmen" version) to $dir/yunmen"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
say "Next: yunmen login https://<your-gateway>"
