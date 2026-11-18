/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* C0F shim: glibc on-disk layout of utmp/wtmp/btmp (384 bytes) and lastlog (292 bytes) for programs built
 * against musl, whose own <utmp.h> describes a different (400/296-byte) layout and whose utmp functions are stubs.
 * Used only to build chkrootkit's chkwtmp, chklastlog and chkutmp so they read real Linux login files. */
#ifndef C0F_SHIM_UTMP_H
#define C0F_SHIM_UTMP_H
#include <stdint.h>
#include <sys/types.h>
#define UT_LINESIZE 32
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256
#define EMPTY 0
#define RUN_LVL 1
#define BOOT_TIME 2
#define NEW_TIME 3
#define OLD_TIME 4
#define INIT_PROCESS 5
#define LOGIN_PROCESS 6
#define USER_PROCESS 7
#define DEAD_PROCESS 8
#define ACCOUNTING 9
#define UTMP_FILE "/var/run/utmp"
#define WTMP_FILE "/var/log/wtmp"
#define UTMP_FILENAME UTMP_FILE
#define WTMP_FILENAME WTMP_FILE
struct exit_status { short e_termination; short e_exit; };
struct utmp {
  short ut_type; short __pad1; int32_t ut_pid; char ut_line[UT_LINESIZE]; char ut_id[4]; char ut_user[UT_NAMESIZE]; char ut_host[UT_HOSTSIZE];
  struct exit_status ut_exit; int32_t ut_session; struct { int32_t tv_sec; int32_t tv_usec; } ut_tv; int32_t ut_addr_v6[4]; char __unused[20];
};
#define ut_name ut_user
#define ut_time ut_tv.tv_sec
#define ut_xtime ut_tv.tv_sec
#define ut_addr ut_addr_v6[0]
struct lastlog { int32_t ll_time; char ll_line[UT_LINESIZE]; char ll_host[UT_HOSTSIZE]; };
_Static_assert(sizeof(struct utmp) == 384, "glibc utmp layout");
_Static_assert(sizeof(struct lastlog) == 292, "glibc lastlog layout");
#define utmpx utmp
#endif
