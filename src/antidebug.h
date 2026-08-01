/*
 * antidebug.h -- Layered anti-debugging for darkcrypt
 */

#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

#include <windows.h>

/* Run all anti-debug checks.
 * Returns TRUE if a debugger is detected, FALSE otherwise. */
BOOL antidebug_check(void);

/* Hide the current thread from debuggers
 * via NtSetInformationThread(ThreadHideFromDebugger). */
void antidebug_hide_thread(void);

#endif /* ANTIDEBUG_H */
