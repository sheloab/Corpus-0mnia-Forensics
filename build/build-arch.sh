#!/bin/sh
# C0F toolkit: build every component for ONE target. Runs inside c0f-build:1 with --network none.
# Usage: build-arch.sh <x86_64|aarch64|armv7>
A=$1
case $A in x86_64) T=x86_64-linux-musl;; aarch64) T=aarch64-linux-musl;; armv7) T=arm-linux-musleabihf;; *) echo bad arch; exit 2;; esac
S=/w/src; B=/w/build/work-$A; P=$B/sys; O=/w/build/out/$A; L=/w/build/logs/$A; WR=$B/wrap
rm -rf $B $O $L; mkdir -p $B $P $O $L $WR
Z=/w/tools/zig/zig
printf '#!/bin/sh\nexec %s cc -target %s "$@"\n' $Z $T > $WR/$T-cc
printf '#!/bin/sh\nexec %s ar "$@"\n' $Z > $WR/$T-ar
printf '#!/bin/sh\nexec %s ranlib "$@"\n' $Z > $WR/$T-ranlib
printf '#!/bin/sh\nexec %s objcopy "$@"\n' $Z > $WR/$T-objcopy
chmod +x $WR/*
export PATH=$WR:$PATH ZIG_GLOBAL_CACHE_DIR=/w/build/zig-cache ZIG_LOCAL_CACHE_DIR=$B/zig-local
export CC=$T-cc AR=$T-ar RANLIB=$T-ranlib PKG_CONFIG_PATH=$P/lib/pkgconfig PKG_CONFIG="pkg-config --static"
export CPPFLAGS="-I$P/include" LDFLAGS="-L$P/lib -static -s" FORCE_UNSAFE_CONFIGURE=1
H=$T
CF="--host=$H --disable-shared --enable-static --prefix=$P"
# cross-compile cache answers (target runtime cannot be probed when cross-compiling)
export ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes scanf_cv_type_modifier=ms
R=/w/build/logs/result-$A.txt; : > $R
step(){ n=$1; shift; s=$(date +%s); ( set -e; "$@" ) > $L/$n.log 2>&1; rc=$?; echo "$A $n rc=$rc secs=$(( $(date +%s)-s ))" >> $R; }
ex(){ d=$B/$1; rm -rf $d; mkdir -p $d; tar -xf $S/$2 -C $d $3; cd $d; }
put(){ src=$1; name=${2:-$(basename $1)}; if [ -f "$src" ]; then cp "$src" $O/$name && chmod 755 $O/$name; else echo "$A MISSING $name" >> $R; fi; }

# ---------- libraries ----------
step libmnl    sh -c "d=$B/mnl; mkdir -p \$d; tar -xf $S/libmnl-1.0.5.tar.bz2 -C \$d --strip-components=1; cd \$d; ./configure $CF; make -j4; make install"
step libnftnl  sh -c "d=$B/nftnl; mkdir -p \$d; tar -xf $S/libnftnl-1.3.2.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF; make -j4; make install"
step sqlite    sh -c "d=$B/sq; mkdir -p \$d; tar -xf $S/sqlite-autoconf-3540000.tar.gz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-readline --disable-editline; make -j4; make install"
step attr      sh -c "d=$B/attr; mkdir -p \$d; tar -xf $S/attr-2.6.0.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-nls; make -j4 LDFLAGS='-L$P/lib -all-static -s'; make install"
step acl       sh -c "d=$B/acl; mkdir -p \$d; tar -xf $S/acl-2.4.0.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-nls; make -j4 LDFLAGS='-L$P/lib -all-static -s'; make install"
step libpcap   sh -c "d=$B/pcap; mkdir -p \$d; tar -xf $S/libpcap-1.11.0.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --without-libnl --disable-dbus --disable-rdma --disable-bluetooth --disable-usb --disable-netmap; make -j4; make install"
step libsodium sh -c "d=$B/sod; mkdir -p \$d; tar -xf $S/libsodium-1.0.22.tar.gz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-pie; make -j4; make install"

# ---------- programs ----------
step busybox sh -c "d=$B/bb; mkdir -p \$d; tar -xf $S/busybox-1.38.0.tar.bz2 -C \$d --strip-components=1; cd \$d; for p in /w/build/patches/busybox-1.38.0-*.patch; do patch -p1 --forward < \$p; done; make defconfig; sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/; s/^CONFIG_TC=y/# CONFIG_TC is not set/' .config; make -j4 CC=$T-cc AR=$T-ar HOSTCC=gcc SKIP_STRIP=y"
put $B/bb/busybox
step coreutils sh -c "d=$B/cu; mkdir -p \$d; tar -xf $S/coreutils-9.12.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-nls --without-selinux --without-openssl --without-gmp --enable-no-install-program=stdbuf; make -j4"
for b in ls stat sha256sum sha1sum md5sum sha512sum date timeout cp dd tee sort uniq cut head tail wc tr stdbuf nice nohup env id who whoami uname readlink realpath du df touch mkdir chmod chown cat printf test basename dirname split base64 b2sum shred; do [ -f $B/cu/src/$b ] && put $B/cu/src/$b; done
step findutils sh -c "d=$B/fu; mkdir -p \$d; tar -xf $S/findutils-4.11.0.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --disable-nls; make -j4"
put $B/fu/find/find; put $B/fu/xargs/xargs
step tar sh -c "d=$B/tar; mkdir -p \$d; tar -xf $S/tar-1.35.tar.xz -C \$d --strip-components=1; cd \$d; ./configure --host=$H --disable-nls --without-posix-acls --without-selinux; make -j4"
put $B/tar/src/tar
step utillinux sh -c "d=$B/ul; mkdir -p \$d; tar -xf $S/util-linux-2.42.4.tar.xz -C \$d --strip-components=1; cd \$d; ./configure --host=$H CC=$T-cc --disable-shared --enable-static --enable-liblastlog2 --enable-lastlog2 --disable-pylibmount --without-python --without-systemd --without-udev --without-ncurses --without-tinfo --without-readline --without-libmagic --without-cap-ng --without-econf --without-selinux --without-audit --without-smack --disable-nls --disable-bash-completion --disable-makeinstall-chown --disable-makeinstall-setuid --disable-asciidoc --disable-poman --disable-login --disable-su --disable-runuser --disable-sulogin --disable-chfn-chsh --disable-newgrp --disable-vipw --disable-liblastlog2-pam --disable-lastlog2-pam 2>&1 | tail -3; make -k -j4 LDFLAGS='-L$P/lib -all-static -s' || true"
for b in last lastlog2 utmpdump lsblk findmnt lsns nsenter hwclock blkid fdisk sfdisk lslocks lsipc dmesg lslogins script flock setsid ionice blockdev wipefs; do put $B/ul/$b; done
step iproute2 sh -c "d=$B/ip2; mkdir -p \$d; tar -xf $S/iproute2-7.3.0.tar.xz -C \$d --strip-components=1; cd \$d; CC=$T-cc AR=$T-ar ./configure; make -j4 CC=$T-cc AR=$T-ar HOSTCC=gcc LDFLAGS='-L$P/lib -static -s' SUBDIRS='lib ip misc bridge'"
put $B/ip2/ip/ip; put $B/ip2/misc/ss; put $B/ip2/bridge/bridge
step e2fsprogs sh -c "d=$B/e2; mkdir -p \$d; tar -xf $S/e2fsprogs-1.47.4.tar.xz -C \$d --strip-components=1; cd \$d; ac_cv_func_lseek64=yes ./configure --host=$H BUILD_CC=gcc --disable-nls --disable-fuse2fs --disable-elf-shlibs --disable-uuidd --disable-fsck CPPFLAGS='-I$P/include -D_LARGEFILE64_SOURCE' LDFLAGS='-L$P/lib -static -s'; make -j4"
put $B/e2/debugfs/debugfs; put $B/e2/misc/e2image; put $B/e2/misc/tune2fs; put $B/e2/misc/dumpe2fs; put $B/e2/misc/lsattr
put $B/attr/getfattr; put $B/acl/getfacl
step libcap sh -c "d=$B/cap; mkdir -p \$d; tar -xf $S/libcap-2.78.tar.xz -C \$d --strip-components=1; cd \$d; make -C libcap SHARED=no GOLANG=no CC=$T-cc BUILD_CC=gcc AR=$T-ar RANLIB=$T-ranlib; make -C progs SHARED=no GOLANG=no CC=$T-cc BUILD_CC=gcc LDFLAGS='-static -s'"
put $B/cap/progs/getcap
step iptables sh -c "d=$B/ipt; mkdir -p \$d; tar -xf $S/iptables-1.8.13.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --enable-nftables; make -j4 LDFLAGS='-L$P/lib -all-static -s'"
put $B/ipt/iptables/xtables-legacy-multi; put $B/ipt/iptables/xtables-nft-multi
step nftables sh -c "d=$B/nft; mkdir -p \$d; tar -xf $S/nftables-1.1.7.tar.xz -C \$d --strip-components=1; cd \$d; ./configure $CF --with-mini-gmp --without-cli --without-json --disable-man-doc --disable-python; make -j4 LDFLAGS='-L$P/lib -all-static -s'"
put $B/nft/src/nft
step ipset sh -c "d=$B/ips; mkdir -p \$d; tar -xf $S/ipset-7.24.tar.bz2 -C \$d --strip-components=1; cd \$d; ./configure $CF --with-kmod=no; make -j4 LDFLAGS='-L$P/lib -all-static -s'"
put $B/ips/src/ipset
step tcpdump sh -c "d=$B/td; mkdir -p \$d; tar -xf $S/tcpdump-4.99.7.tar.xz -C \$d --strip-components=1; cd \$d; ./configure --host=$H --without-crypto --with-pcap=$P; make -j4 LDFLAGS='-L$P/lib -static -s'"
put $B/td/tcpdump
step procps sh -c "d=$B/ps; mkdir -p \$d; tar -xf $S/procps-v4.0.7-gitlab.tar.gz -C \$d --strip-components=1; cd \$d; echo 4.0.7 > .tarball-version; ./autogen.sh; ./configure $CF --disable-nls --without-ncurses --without-systemd --without-elogind; make -j4 LDFLAGS='-L$P/lib -all-static -s'"
put $B/ps/src/ps/pscommand ps; for b in pgrep pkill w pmap free uptime vmstat sysctl pwdx; do put $B/ps/src/$b; done
step lsof sh -c "d=$B/lsof; mkdir -p \$d; tar -xf $S/lsof-4.99.7.tar.gz -C \$d --strip-components=1; cd \$d; ./configure --host=$H --disable-shared; make -j4 lsof LDFLAGS='-static -s'"
put $B/lsof/lsof
step dmidecode sh -c "d=$B/dmi; mkdir -p \$d; tar -xf $S/dmidecode-3.7.tar.xz -C \$d --strip-components=1; cd \$d; make CC=$T-cc LDFLAGS='-static -s'"
put $B/dmi/dmidecode
# file: cross builds need the same-version 'file' on the build machine -> use the x86_64 one built earlier
FILEHOST=/w/build/out/x86_64/file
step file sh -c "d=$B/file; mkdir -p \$d; tar -xf $S/file-5.48.tar.gz -C \$d --strip-components=1; cd \$d; mkdir -p hostbin; [ -x $FILEHOST ] && [ $A != x86_64 ] && cp $FILEHOST hostbin/file; PATH=\$PWD/hostbin:\$PATH ./configure $CF --disable-zlib --disable-bzlib --disable-xzlib --disable-zstdlib --disable-lzlib; PATH=\$PWD/hostbin:\$PATH make -j4 LDFLAGS='-L$P/lib -all-static -s'"
put $B/file/src/file; mkdir -p $O/../share; [ -f $B/file/magic/magic.mgc ] && cp $B/file/magic/magic.mgc /w/build/out/magic-$A.mgc
step minisign sh -c "d=$B/ms; mkdir -p \$d; tar -xf $S/minisign-0.12.tar.gz -C \$d --exclude='._*'; cd \$d; $T-cc -O2 -static -s -I$P/include src/*.c -L$P/lib -lsodium -o minisign"
put $B/ms/minisign
step chkrootkit sh -c "d=$B/chk; mkdir -p \$d; tar -xf $S/chkrootkit_0.58b.orig.tar.gz -C \$d --strip-components=1; cd \$d; tar -xJf $S/chkrootkit_0.58b-5.debian.tar.xz; for p in \$(grep -v '^#' debian/patches/series); do patch -p1 --forward < debian/patches/\$p; done; make sense CC=$T-cc STATIC=-static LDFLAGS='-static -s' CFLAGS='-include fcntl.h -include sys/types.h -D__fsword_t=long'"
mkdir -p $O/chkrootkit; for b in chkproc chkdirs ifpromisc chklastlog chkwtmp chkutmp strings-static check_wtmpx; do [ -f $B/chk/$b ] && cp $B/chk/$b $O/chkrootkit/ && chmod 755 $O/chkrootkit/$b || echo "$A MISSING chkrootkit/$b" >> $R; done; [ -f $B/chk/chkrootkit ] && cp $B/chk/chkrootkit $O/chkrootkit/chkrootkit && chmod 755 $O/chkrootkit/chkrootkit
echo "$A BUILD-DONE" >> $R
