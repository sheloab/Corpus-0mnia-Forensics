#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Build and sign a C0F release. Run in a real terminal (minisign asks the key password twice).
#   sh kit/release.sh /path/to/c0f-minisign.key
# Output: release/<version>/
#   C0F-<version>.tar.gz                       ready-to-use kit (C0F-KIT/, all architectures, signed SHA256SUMS inside)
#   C0F-<version>-third-party-sources.tar      exact upstream sources + signatures + build scripts (GPL/LGPL)
#   c0f-minisign.pub                           release public key
#   RELEASE-SHA256SUMS.txt (+ .minisig)        SHA-256 of the files above, signed
set -eu
R=$(cd "$(dirname "$0")/.." && pwd); KIT=$R/kit/C0F-KIT; V=$(cat "$R/kit-src/VERSION"); KEY=${1:?usage: release.sh SECRET_KEY}
MS=$R/tools/minisign-linux/x86_64/minisign; OUT=$R/release/$V
OFFICIAL=RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p
[ "$(tail -n 1 "$KIT/minisign.pub")" = "$OFFICIAL" ] || { echo "kit/C0F-KIT/minisign.pub is not the official release key"; exit 1; }
[ -e "$OUT" ] && { echo "$OUT exists: remove it first"; exit 1; }
mkdir -p "$OUT"

echo "== 1/3 sign the kit (key password)"
C0F_SIGN_INTERACTIVE=1 sh "$R/kit/mksums.sh" "$KIT" "$KEY" "C0F $V - official release"
"$MS" -Vm "$KIT/SHA256SUMS" -P "$OFFICIAL" >/dev/null
( cd "$KIT" && bin/x86_64/sha256sum -c --quiet SHA256SUMS )
echo "kit signature and all files OK"

echo "== 2/3 build release archives"
MT=$(( $(stat -c %Y "$KIT/SHA256SUMS") / 86400 * 86400 ))   # release day, 00:00 UTC
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$MT" -C "$R/kit" -cf - C0F-KIT | gzip -n -9 > "$OUT/C0F-$V.tar.gz"
T=$OUT/.tp; mkdir -p "$T/C0F-$V-third-party-sources/upstream" "$T/C0F-$V-third-party-sources/signatures"
S=$T/C0F-$V-third-party-sources
# every upstream source archive the kit was built from (toolchain and the prebuilt minisign excluded: not shipped)
awk '{print $2}' "$R/SHA256SUMS.sources" | grep -vE '^(zig-|minisign-0\.12-linux)' | while read -r f; do cp "$R/src/$f" "$S/upstream/"; done
cp "$R/src/7z2605-src.tar.xz" "$S/upstream/"
cp "$R"/sig/* "$S/signatures/"; cp -R "$R/keys" "$S/upstream-signing-keys"
( cd "$S/upstream" && sha256sum * > ../SHA256SUMS.upstream )
mkdir -p "$S/c0f-build"
cp -R "$R/kit-src" "$S/c0f-build/"; rm -rf "${S:?}/c0f-build/kit-src/tools/__pycache__"; cp "$R"/build/*.sh "$S/c0f-build/" 2>/dev/null || true; cp -R "$R/build/patches" "$S/c0f-build/"
mkdir -p "$S/c0f-build/helpers"; cp -R "$R/helpers/src" "$R/helpers/shim-glibc-utmp" "$R/helpers/build-helpers.sh" "$R/helpers/fix-chk-utmp.sh" "$S/c0f-build/helpers/"
cp "$R/buildimg/Dockerfile" "$R/fetch.sh" "$R/kit/assemble.sh" "$R/kit/mksums.sh" "$S/c0f-build/"
cat > "$S/README.txt" <<EOF
C0F $V - third-party source code

upstream/                 the exact, unmodified source archives used to build the programs in bin/ of the kit
                          (SHA256SUMS.upstream; the same hashes are in BUILDINFO.txt of the kit), including
                          chkrootkit 0.58b + the Debian 0.58b-5 patch set and 7-Zip 26.05 (7zzs, LGPL-2.1)
signatures/               the upstream signatures/checksums used to verify them
upstream-signing-keys/    the upstream OpenPGP keys
c0f-build/                C0F build scripts, patches (patches/: BusyBox ash read fix; chkrootkit utmp shim) and C0F helper
                          sources; build: offline container from Dockerfile, zig cc 0.17.1 (musl, static)
Licenses of each program: LICENSES/ in the kit.
EOF
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$MT" -C "$T" -cf "$OUT/C0F-$V-third-party-sources.tar" "C0F-$V-third-party-sources"
rm -rf "${T:?}"
cp "$KIT/minisign.pub" "$OUT/c0f-minisign.pub"
( cd "$OUT" && sha256sum "C0F-$V.tar.gz" "C0F-$V-third-party-sources.tar" c0f-minisign.pub > RELEASE-SHA256SUMS.txt )

echo "== 3/3 sign the release checksum list (key password)"
"$MS" -Sm "$OUT/RELEASE-SHA256SUMS.txt" -s "$KEY" -t "C0F $V - official release files"
"$MS" -Vm "$OUT/RELEASE-SHA256SUMS.txt" -P "$OFFICIAL"
( cd "$OUT" && sha256sum -c RELEASE-SHA256SUMS.txt )
if [ "$(id -u)" = 0 ]; then chown -R "$(stat -c %u:%g "$R")" "$R/release" "$KIT/SHA256SUMS" "$KIT/SHA256SUMS.minisig"; fi
ls -la "$OUT"
echo "DONE."
