#!/bin/sh
# Rebuild e2fsprogs for one arch with -D_LARGEFILE64_SOURCE (musl hides lseek64 otherwise; matters on 32-bit). Usage: fix-e2fs.sh <arch>
A=$1; case $A in x86_64) T=x86_64-linux-musl;; aarch64) T=aarch64-linux-musl;; armv7) T=arm-linux-musleabihf;; esac
S=/w/src; B=/w/build/work-$A; P=$B/sys; O=/w/build/out/$A; R=/w/build/logs/result-$A.txt
export PATH=$B/wrap:$PATH ZIG_GLOBAL_CACHE_DIR=/w/build/zig-cache CC=$T-cc AR=$T-ar RANLIB=$T-ranlib
d=$B/e2; rm -rf $d; mkdir -p $d; tar -xf $S/e2fsprogs-1.47.4.tar.xz -C $d --strip-components=1; cd $d
( ac_cv_func_lseek64=yes ./configure --host=$T BUILD_CC=gcc --disable-nls --disable-fuse2fs --disable-elf-shlibs --disable-uuidd --disable-fsck CPPFLAGS="-I$P/include -D_LARGEFILE64_SOURCE" LDFLAGS="-L$P/lib -static -s" && make -j4 ) > /w/build/logs/$A/e2fsprogs-fix.log 2>&1; rc=$?
echo "$A e2fsprogs-fix rc=$rc" >> $R
for f in debugfs/debugfs misc/e2image misc/tune2fs misc/dumpe2fs misc/lsattr; do [ -f $f ] && cp $f $O/ && chmod 755 $O/$(basename $f) || echo "$A MISSING $(basename $f) (after fix)" >> $R; done
