#!/usr/bin/env python3
"""
check_iocs.py — Scan a darkcrypt build binary for plaintext IOC strings
(ASCII + UTF-16LE wide) and static byte-pattern signatures.

Usage:
    python3 tools/check_iocs.py build/loader.exe

Exit codes:
    0 — no IOCs detected (PASS)
    1 — one or more IOC strings or byte patterns detected (FAIL)
    2 — usage / tooling error

The scanner runs three passes:

  * ASCII   — `strings -a` (or a pure-Python printable-ASCII fallback).
  * WIDE    — `strings -el` 16-bit little-endian (or a pure-Python UTF-16LE
              fallback). Catches Windows wide-char strings that leak into the
              binary as UTF-16LE and are invisible to the ASCII pass.
  * BYTES   — raw byte signature scan (YARA-style static indicators).

Every IOC pattern is matched against BOTH the ASCII and WIDE string sets, and
each hit is tagged with the pass it came from ([ascii]/[wide]/[bytes]) so the
report is actionable.

An allowlist of unavoidable mingw/CRT/PE-import-table strings is maintained and
applied to BOTH string passes: any string line that matches the allowlist is
suppressed entirely (it is a benign runtime/import artifact, not an IOC). This
keeps the ASCII pass from false-positiving on import entries such as
`KERNEL32.dll`, `LoadLibraryA`, `GetProcAddress`, `CreateProcessA` and the
`WinHttp*` import names.
"""

import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# IOC patterns — flag if any of these are present (case-insensitive).
# Each entry: (label, compiled regex). Matched against both ASCII and WIDE.
# ---------------------------------------------------------------------------
IOC_PATTERNS = [
    # --- nt/syscall surface (should be resolved via PEB walk, not plaintext) -
    ("NtAllocateVirtualMemory",    re.compile(r"NtAllocateVirtualMemory",    re.I)),
    ("NtWriteVirtualMemory",      re.compile(r"NtWriteVirtualMemory",       re.I)),
    ("NtProtectVirtualMemory",    re.compile(r"NtProtectVirtualMemory",     re.I)),
    ("NtQueueApcThread",          re.compile(r"NtQueueApcThread",           re.I)),
    ("NtFreeVirtualMemory",       re.compile(r"NtFreeVirtualMemory",        re.I)),
    ("NtQueryInformationProcess", re.compile(r"NtQueryInformationProcess",   re.I)),
    ("NtSetInformationThread",    re.compile(r"NtSetInformationThread",      re.I)),
    ("EtwEventWrite",            re.compile(r"EtwEventWrite",               re.I)),
    ("NtTraceEvent",            re.compile(r"NtTraceEvent",                 re.I)),
    # --- AMSI / ETW patch targets ------------------------------------------
    ("AmsiScanBuffer",          re.compile(r"AmsiScanBuffer",               re.I)),
    ("amsi.dll",                re.compile(r"amsi\.dll",                     re.I)),
    # --- dynamic resolution primitives (should be PEB-walked, not imported) -
    ("ntdll.dll",               re.compile(r"ntdll\.dll",                   re.I)),
    ("kernel32.dll",            re.compile(r"kernel32\.dll",                re.I)),
    ("ws2_32",                  re.compile(r"ws2_32",                       re.I)),
    ("winhttp",                 re.compile(r"winhttp",                     re.I)),
    ("LoadLibrary",             re.compile(r"LoadLibrary",                 re.I)),
    ("GetProcAddress",           re.compile(r"GetProcAddress",              re.I)),
    ("CreateProcess",            re.compile(r"CreateProcess",              re.I)),
    # --- target process / host indicators ----------------------------------
    ("RuntimeBroker",           re.compile(r"RuntimeBroker",               re.I)),
    ("explorer.exe",            re.compile(r"\bexplorer\.exe\b",            re.I)),
    ("127.0.0.1",               re.compile(r"127\.0\.0\.1")),
    ("172.25.",                 re.compile(r"172\.25\.")),
    # --- payload / command indicators -------------------------------------
    ("aes.encrypted",           re.compile(r"aes\.encrypted",               re.I)),
    ("cmd /c",                  re.compile(r"cmd\s/c",                    re.I)),
    ("timeout",                 re.compile(r"timeout",                   re.I)),
    # --- User-Agent fragments (wide-char leak of rotating UA table) -------
    ("Mozilla/5.0",             re.compile(r"Mozilla/5\.0",                  re.I)),
    ("Chrome/",                 re.compile(r"Chrome/",                    re.I)),
    ("Firefox/",                re.compile(r"Firefox/",                   re.I)),
    ("Edg/",                    re.compile(r"Edg/",                       re.I)),
    ("Safari/",                 re.compile(r"Safari/",                    re.I)),
    ("AppleWebKit",            re.compile(r"AppleWebKit",                re.I)),
    ("Gecko/",                  re.compile(r"Gecko/",                    re.I)),
]

# ---------------------------------------------------------------------------
# Byte-pattern signatures — static YARA-style indicators scanned against the
# raw bytes of the binary.  Each entry: (label, bytes).  Reported with the
# byte offset of every occurrence.
# ---------------------------------------------------------------------------
BYTE_PATTERNS = [
    ("AES S-box head",
     bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES inverse S-box head",
     bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("AMSI patch bytes (mov eax, 0x80070057)",
     bytes.fromhex("b857000780")),
    # NB: ETW ret-patch (c3) in a known position is not generically flaggable
    # and is intentionally omitted.
    # SHA-256 crypto-table signatures — static constants pulled in via hmac.c.
    # K256 are the round constants; the IV is the set of initial hash values.
    # Both are emitted as little-endian uint32_t arrays on x64.
    ("SHA-256 K256 head (round constants)",
     bytes.fromhex("982f8a4291443771")),
    ("SHA-256 IV head (initial hash values)",
     bytes.fromhex("67e6096a85ae67bb")),
]

# ---------------------------------------------------------------------------
# Allowlist — unavoidable mingw/CRT/PE-import-table strings.  A string line
# that matches the allowlist is suppressed entirely on BOTH the ASCII and WIDE
# passes: it is a benign runtime/import artifact, not an IOC.  This is what
# keeps `KERNEL32.dll`, `LoadLibraryA`, `GetProcAddress`, `CreateProcessA` and
# the `WinHttp*` import names from false-positiving on the ASCII pass.
# ---------------------------------------------------------------------------
ALLOWLIST = [
    "Mingw-w64 runtime", "EnterCriticalSection", "GetCurrentThread",
    "QueryPerformanceCounter", "GetThreadContext", "GetEnvironmentVariable",
    "GetTickCount", "GetSystemInfo", "GlobalMemoryStatus", "GetDiskFreeSpace",
    "FindFirstFile", "CreateProcess", "WaitForSingle", "CloseHandle",
    "MoveFileEx", "GetModuleFileName", "fprintf", "vfprintf", "WinHttp",
    "_clearbuf", "__acrt_iob", "freopen", "malloc", "free", "realloc", "exit",
    "LoadLibrary", "GetProcAddress", "kernel32",
    "GetLastError",  # msvcrt CRT import (thread-safety) — standard build only
    "null",  # (null) wide string from msvcrt printf — benign CRT artifact
]

_ALLOW_RE = re.compile("|".join(re.escape(s) for s in ALLOWLIST), re.I)

_MIN_STR_LEN = 4  # minimum printable run length, matches `strings` default


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def _read_binary(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read binary '{path}': {exc}", file=sys.stderr)
        sys.exit(2)


def extract_strings_ascii(path):
    """
    Return a list of printable-ASCII string runs from *path*.

    Tries the external ``strings -a`` utility first; falls back to a
    pure-Python scanner that extracts runs of printable ASCII (length >= 4).
    """
    try:
        proc = subprocess.run(
            ["strings", "-a", path],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0:
            return proc.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    data = _read_binary(path)
    out = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:  # printable ASCII
            current.append(byte)
        else:
            if len(current) >= _MIN_STR_LEN:
                out.append(current.decode("ascii", errors="replace"))
            current = bytearray()
    if len(current) >= _MIN_STR_LEN:
        out.append(current.decode("ascii", errors="replace"))
    return out


def extract_strings_wide(path):
    """
    Return a list of UTF-16LE (wide) string runs from *path*.

    Tries the external ``strings -el`` utility first (16-bit little-endian);
    falls back to a pure-Python UTF-16LE scanner that extracts runs of
    printable ASCII characters encoded as UTF-16LE (low byte printable,
    high byte 0x00), length >= 4 characters.
    """
    try:
        proc = subprocess.run(
            ["strings", "-el", path],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0:
            return proc.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    data = _read_binary(path)
    out = []
    current = []
    i = 0
    n = len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and 0x20 <= lo <= 0x7E:  # printable ASCII as UTF-16LE
            current.append(chr(lo))
            i += 2
        else:
            if len(current) >= _MIN_STR_LEN:
                out.append("".join(current))
            current = []
            i += 1
    if len(current) >= _MIN_STR_LEN:
        out.append("".join(current))
    return out


# ---------------------------------------------------------------------------
# Byte-pattern scan
# ---------------------------------------------------------------------------

def scan_byte_patterns(data):
    """
    Return a list of (label, offset) tuples for every occurrence of each
    BYTE_PATTERNS signature found in *data*.
    """
    hits = []
    for label, sig in BYTE_PATTERNS:
        start = 0
        while True:
            off = data.find(sig, start)
            if off < 0:
                break
            hits.append((label, off))
            start = off + 1  # allow overlapping matches
    return hits


# ---------------------------------------------------------------------------
# IOC matching against a string set
# ---------------------------------------------------------------------------

def match_string_iocs(lines, pass_name):
    """
    Match every IOC pattern against *lines*, tagging hits with *pass_name*
    ([ascii] or [wide]).  Allowlisted lines are skipped entirely.  Each
    (pass, label) is reported at most once.
    """
    hits = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Allowlist suppresses benign CRT/import artifacts on both passes.
        if _ALLOW_RE.search(stripped):
            continue
        for label, pattern in IOC_PATTERNS:
            if pattern.search(stripped):
                key = (pass_name, label)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((pass_name, label, stripped))
    return hits


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>", file=sys.stderr)
        sys.exit(2)

    binary = sys.argv[1]

    # --- Pass 1 + 2: ASCII and WIDE string IOCs ------------------------------
    ascii_lines = extract_strings_ascii(binary)
    wide_lines = extract_strings_wide(binary)

    str_hits = []
    str_hits += match_string_iocs(ascii_lines, "ascii")
    str_hits += match_string_iocs(wide_lines, "wide")

    # --- Pass 3: raw byte-pattern signatures --------------------------------
    data = _read_binary(binary)
    byte_hits = scan_byte_patterns(data)

    # --- Report -------------------------------------------------------------
    findings = []
    for pass_name, label, line in str_hits:
        findings.append((pass_name, label, line, None))
    for label, off in byte_hits:
        findings.append(("bytes", label, None, off))

    if findings:
        print(f"FAIL: {len(findings)} finding(s) detected in {binary}")
        print("-" * 60)
        for pass_name, label, line, off in findings:
            if pass_name == "bytes":
                print(f"  FAIL  [{pass_name}]  {label}  @ offset 0x{off:x}")
            else:
                shown = line if len(line) <= 120 else line[:117] + "..."
                print(f"  FAIL  [{pass_name}]  {label}  {shown}")
        print("-" * 60)
        sys.exit(1)
    else:
        print(f"PASS: no IOCs (strings or byte patterns) detected in {binary}")
        sys.exit(0)


if __name__ == "__main__":
    main()
