#!/usr/bin/env bash
# Cross-compiles OctoLAN for every supported platform into ./dist.
# Each binary is a single static file: copy it to a laptop/router and run.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.Version=${VERSION}"
rm -rf dist && mkdir -p dist

targets=(
  "windows amd64 .exe"
  "windows arm64 .exe"
  "darwin  arm64"
  "darwin  amd64"
  "linux   amd64"
  "linux   arm64"
  "linux   arm GOARM=7"
  "linux   mipsle GOMIPS=softfloat"
  "linux   mips   GOMIPS=softfloat"
)
for t in "${targets[@]}"; do
  read -r os arch rest <<<"$t"
  ext=""; extra=()
  for x in $rest; do
    case "$x" in .exe) ext=".exe" ;; *=*) extra+=("$x") ;; esac
  done
  out="dist/octolan-${os}-${arch}${ext}"
  echo "→ ${out}"
  env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" ${extra[@]+"${extra[@]}"} \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/octolan
done
# Universal macOS binary when lipo is available.
if command -v lipo >/dev/null; then
  lipo -create -output dist/octolan-darwin-universal dist/octolan-darwin-arm64 dist/octolan-darwin-amd64
fi
(cd dist && shasum -a 256 octolan-* > SHA256SUMS)
ls -lh dist
