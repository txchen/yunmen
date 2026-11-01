#!/usr/bin/env bash
# Build CLI release archives and checksums.
#   scripts/build-cli-release.sh <version> <out-dir>
# Linux and macOS get .tar.gz archives; Windows gets .zip with yunmen.exe.
set -euo pipefail
version=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name=yunmen_${version}_${os}_${arch}
  exe=yunmen
  [ "$os" = windows ] && exe=yunmen.exe
  mkdir -p "$build/$name"
  (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X github.com/txchen/yunmen/internal/version.Version=${version}" \
    -o "$build/$name/$exe" ./cmd/yunmen)
  cp "$root/LICENSE" "$root/README.md" "$build/$name/"
  if [ "$os" = windows ]; then
    (cd "$build" && zip -qr "$out/$name.zip" "$name")
  else
    tar -C "$build" -czf "$out/$name.tar.gz" "$name"
  fi
done
(cd "$out" && sha256sum ./*.tar.gz ./*.zip | sed 's# \./# #' > checksums.txt)
