#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Rebuild chkwtmp, chklastlog, chkutmp with the glibc-layout utmp shim. Runs in c0f-build:1, --network none.
Z=/w/tools/zig/zig; export ZIG_GLOBAL_CACHE_DIR=/w/build/zig-cache ZIG_LOCAL_CACHE_DIR=/tmp/zl; rc=0
for A in x86_64 aarch64 armv7; do
  case $A in x86_64) T=x86_64-linux-musl;; aarch64) T=aarch64-linux-musl;; armv7) T=arm-linux-musleabihf;; esac
  C=/w/build/work-$A/chk
  # C0F patch: chkwtmp passes &long to ctime(time_t*) -> wrong date where time_t is 64-bit and long is 32-bit (armv7)
  sed -e 's/void printit(int counter, long start, long end)/void printit(int counter, time_t start, time_t end)/' \
      -e 's/^\(\s*\)long\(\s*\)start_time, act_time;/\1time_t\2start_time, act_time;/' $C/chkwtmp.c > /tmp/chkwtmp.c
  grep -q 'time_t start, time_t end' /tmp/chkwtmp.c && grep -q 'time_t.*start_time, act_time' /tmp/chkwtmp.c || { echo "chkwtmp patch did not apply"; exit 1; }
  for b in chkwtmp chklastlog chkutmp; do
    src=$C/$b.c; [ $b = chkwtmp ] && src=/tmp/chkwtmp.c
    if $Z cc -target $T -O2 -I/w/helpers/shim-glibc-utmp -include fcntl.h -include sys/types.h -D__fsword_t=long -static -s -o /tmp/$b-$A $src 2>/w/helpers/logs/chk-$A-$b.log; then
      cp /tmp/$b-$A /w/build/out/$A/chkrootkit/$b; chmod 755 /w/build/out/$A/chkrootkit/$b; echo "$A $b OK"; else echo "$A $b FAIL"; rc=1; cat /w/helpers/logs/chk-$A-$b.log | head; fi
  done
done
# glibc reference build of chkwtmp/chklastlog (native gcc, system headers) for comparison
gcc -O2 -include fcntl.h -o /w/helpers/test/ref/chkwtmp.glibc /w/build/work-x86_64/chk/chkwtmp.c 2>/dev/null && echo "ref chkwtmp OK"
gcc -O2 -include fcntl.h -o /w/helpers/test/ref/chklastlog.glibc /w/build/work-x86_64/chk/chklastlog.c 2>/dev/null && echo "ref chklastlog OK"
exit $rc
