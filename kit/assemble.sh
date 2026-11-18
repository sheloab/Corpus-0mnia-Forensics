#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# C0F: assemble C0F-KIT/bin/<arch> from our builds + official vendor binaries. Re-runnable (rebuilds bin/ from scratch).
set -eu
W=$(cd "$(dirname "$0")/.." && pwd); K=$W/kit/C0F-KIT; OFF=$W/bin-official; X=$W/kit/extract
LOG=$W/kit/assemble.log; : > $LOG
(cd $OFF && sha256sum -c --quiet ../SHA256SUMS.official) || { echo "official hash check FAILED" | tee -a $LOG; exit 1; }
echo "official hashes OK $(date -u +%FT%TZ)" >> $LOG
rm -rf $K/bin $K/share $X; mkdir -p $K/share $X
cp $W/build/out/magic-x86_64.mgc $K/share/magic.mgc; chmod 644 $K/share/magic.mgc
for A in x86_64 aarch64 armv7; do
  case $A in x86_64) D=x86_64; K8=amd64; Z=x64; J=amd64; AV=avml;;
             aarch64) D=aarch64; K8=arm64; Z=arm64; J=arm64; AV=avml-aarch64;;
             armv7) D=armhf; K8=arm; Z=arm; J=armhf; AV=;; esac
  B=$K/bin/$A; mkdir -p $B $X/$A
  cp -pR $W/build/out/$A/. $B/
  tar -xzf $OFF/docker-29.9.3-$D.tgz -C $X/$A docker/docker docker/ctr docker/runc
  cp $X/$A/docker/docker $X/$A/docker/ctr $X/$A/docker/runc $B/
  tar -xJf $OFF/7z2605-linux-$Z.tar.xz -C $X/$A 7zzs License.txt; cp $X/$A/7zzs $B/
  cp $OFF/kubectl-1.37.2-$K8 $B/kubectl
  cp $OFF/jq-1.8.2-linux-$J $B/jq
  [ -f $OFF/crictl-v1.37.0-linux-$K8.tar.gz ] && { tar -xzf $OFF/crictl-v1.37.0-linux-$K8.tar.gz -C $X/$A crictl; cp $X/$A/crictl $B/; }
  [ -n "$AV" ] && cp $OFF/avml-0.21.0-$AV $B/avml
  # C0F helpers (own source, helpers/src)
  for h in c0f-copy c0f-logins c0f-memdump c0f-sshkey c0f-x11; do cp $W/helpers/out/$A/$h $B/; done
  # musl utmp API is a stub and its struct utmp differs from glibc: these return empty/wrong data on real
  # Linux login files (verified 2026-11-17). Login records are parsed by c0f-logins instead.
  rm -f $B/last $B/utmpdump $B/who $B/w
  find $B -type f -exec chmod 755 {} +
  echo "$A files=$(find $B -type f | wc -l) bytes=$(du -sb $B | cut -f1)" >> $LOG
done
cp $X/x86_64/License.txt $W/kit/7zip-License.txt
rm -rf $X
cat $LOG
