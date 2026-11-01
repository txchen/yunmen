#!/usr/bin/env bash
# Build CLI release archives and checksums.
#   scripts/build-cli-release.sh <version> <out-dir>
set -euo pipefail
version=$1
out=$2
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
mkdir -p "$out"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name=yunmen_${version}_${os}_${arch}
  mkdir -p "$build/$name"
  (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X github.com/txchen/yunmen/internal/version.Version=${version}" \
    -o "$build/$name/yunmen" ./cmd/yunmen)
  cp "$root/LICENSE" "$root/README.md" "$build/$name/"
  tar -C "$build" -czf "$out/$name.tar.gz" "$name"
done
(cd "$out" && sha256sum ./*.tar.gz | sed 's# \./# #' > checksums.txt)
