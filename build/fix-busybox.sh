#!/bin/sh
# Rebuild only BusyBox for one arch (strip step skipped; binary is already linked with -s). Usage: fix-busybox.sh <arch>
A=$1; case $A in x86_64) T=x86_64-linux-musl;; aarch64) T=aarch64-linux-musl;; armv7) T=arm-linux-musleabihf;; esac
B=/w/build/work-$A; O=/w/build/out/$A; R=/w/build/logs/result-$A.txt; export PATH=$B/wrap:$PATH ZIG_GLOBAL_CACHE_DIR=/w/build/zig-cache
cd $B/bb && make -j4 CC=$T-cc AR=$T-ar HOSTCC=gcc SKIP_STRIP=y > /w/build/logs/$A/busybox-fix.log 2>&1; rc=$?
echo "$A busybox-fix rc=$rc" >> $R; [ -f busybox ] && cp busybox $O/busybox && chmod 755 $O/busybox || echo "$A MISSING busybox (after fix)" >> $R
