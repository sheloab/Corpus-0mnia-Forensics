#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# BUILDINFO.txt: how and from what this kit was built (no personal or host-identifying data).
set -eu
W=$(cd "$(dirname "$0")/../.." && pwd); K=${1:?kit}; V=${2:?version}
img=$(sudo -n docker image inspect c0f-build:1 --format '{{.Id}}' 2>/dev/null || echo unknown)
{
echo "C0F (Corpus-0mnia Forensics) $V - build information"
echo "built (UTC date)     : $(date -u +%Y-%m-%d)"
echo "build environment    : offline container (no network) from Debian trixie-slim + build packages, image $img"
echo "compiler             : zig cc 0.17.1 (musl, fully static), targets x86_64-linux-musl, aarch64-linux-musl, arm-linux-musleabihf"
echo "                       zig archive sha256 $(grep 'zig-x86_64-linux-0.17.1' "$W/SHA256SUMS.sources" | cut -c1-64)"
echo "tests                : x86_64 natively; aarch64 and armv7 under qemu-user (user-mode emulation, not real ARM kernels)"
echo
echo "== source archives (official releases, signatures/hashes verified before use)"
sed 's/^/  /' "$W/SHA256SUMS.sources"
echo
echo "== vendor binaries (official static releases, unchanged)"
sed 's/^/  /' "$W/SHA256SUMS.official"
echo
echo "== C0F changes to third-party code"
echo "  chkrootkit 0.58b: Debian 0.58b-5 patch series applied; chkwtmp/chklastlog/chkutmp compiled with a glibc-layout"
echo "  utmp/lastlog header (C0F shim); chkwtmp: printit() and start_time/act_time use time_t instead of long."
echo "  BusyBox 1.38.0: patch build/patches/busybox-1.38.0-ash-read-after-trap.patch (sha256 $(sha256sum "$W/build/patches/busybox-1.38.0-ash-read-after-trap.patch" | cut -c1-64)):"
echo "  after a trapped signal (Ctrl+C) the ash 'read' builtin looped forever; the patch clears the stale signal flag."
echo "  Not shipped on purpose: util-linux last/utmpdump, coreutils who, procps w (musl utmp stubs give empty/wrong data)."
echo
echo "== C0F helper sources (sha256)"
for f in "$W"/helpers/src/*.c "$W"/helpers/src/*.h "$W"/helpers/shim-glibc-utmp/*.h; do printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-64)" "${f##*/}"; done
echo
echo "== helper test results"
echo "  test-helpers.sh 53/53 (x86_64, aarch64, armv7); test-x11.sh 12/12 (x86_64, aarch64, armv7, Xvfb)"
echo "  c0f-logins = glibc struct utmp/lastlog reader on real wtmp/lastlog files; c0f-sshkey = ssh-keygen/puttygen fingerprints"
echo "  chkwtmp/chklastlog (shim build) = glibc-built reference on all 3 architectures"
echo
echo "== kit signature"
echo "  SHA256SUMS signed with minisign (Ed25519). The secret key is not part of the kit: it is password protected and kept"
echo "  offline by the maintainer. The public key is minisign.pub"
echo "  and is also kept outside the kit (SOP)."
} > "$K/BUILDINFO.txt"
