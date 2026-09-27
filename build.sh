#!/usr/bin/env bash
# Builds index.html: a single self-contained page with the SOPS core compiled
# to WebAssembly and embedded in it. Requires Go and Node.js.
set -euo pipefail
cd "$(dirname "$0")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

(cd wasm && GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w -buildid=" -o "$tmp/core.wasm" .)
gzip -9 -n -c "$tmp/core.wasm" > "$tmp/core.wasm.gz"

goroot="$(go env GOROOT)"
wasm_exec="$goroot/lib/wasm/wasm_exec.js"
[ -f "$wasm_exec" ] || wasm_exec="$goroot/misc/wasm/wasm_exec.js"

node scripts/inline.mjs web/app.html "$wasm_exec" "$tmp/core.wasm.gz" > index.html
echo "Built index.html ($(du -h index.html | cut -f1), $(go version | cut -d' ' -f3))"
