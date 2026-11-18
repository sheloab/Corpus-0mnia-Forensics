#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Build the C0F helpers for all 3 targets. Runs inside c0f-build:1 with --network none.
set -u
Z=/w/tools/zig/zig; S=/w/helpers/src; export ZIG_GLOBAL_CACHE_DIR=/w/build/zig-cache ZIG_LOCAL_CACHE_DIR=/tmp/zl
rc=0
for A in x86_64 aarch64 armv7; do
  case $A in x86_64) T=x86_64-linux-musl;; aarch64) T=aarch64-linux-musl;; armv7) T=arm-linux-musleabihf;; esac
  O=/w/helpers/out/$A; rm -rf $O; mkdir -p $O
  for h in c0f-copy c0f-logins c0f-memdump c0f-sshkey c0f-x11; do
    if $Z cc -target $T -std=gnu11 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -static -s -o $O/$h $S/$h.c 2>/w/helpers/logs/$A-$h.log; then echo "$A $h OK"; else echo "$A $h FAIL"; rc=1; fi
    [ -s /w/helpers/logs/$A-$h.log ] && sed 's/^/   /' /w/helpers/logs/$A-$h.log | head -30
  done
done
exit $rc
