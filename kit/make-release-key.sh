#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Create the C0F release signing key (password typed by the maintainer) and sign the kit with it.
# Run in a real terminal (it asks for the password): sh kit/make-release-key.sh   (from the repository root)
set -eu
W=$(cd "$(dirname "$0")/.." && pwd); KIT=$W/kit/C0F-KIT; MS=$W/tools/minisign-linux/x86_64/minisign; D=${C0F_KEYDIR:-/srv/c0f-key}   # private folder for the new key
V=$(cat "$W/kit-src/VERSION")
[ -d "$D" ] || { echo "missing $D"; exit 1; }
if [ -e "$D/c0f-minisign.key" ]; then echo "$D/c0f-minisign.key already exists: not overwritten"; exit 1; fi
echo "== 1/3 create the key: choose a strong password (asked twice). Without it the key cannot sign."
( umask 077; "$MS" -G -p "$D/c0f-minisign.pub" -s "$D/c0f-minisign.key" -c "C0F release signing key" )
cp "$D/c0f-minisign.pub" "$KIT/minisign.pub"; chmod 644 "$KIT/minisign.pub"
echo
echo "== 2/3 sign the kit (type the same password once)"
C0F_SIGN_INTERACTIVE=1 sh "$W/kit/mksums.sh" "$KIT" "$D/c0f-minisign.key" "C0F $V - official release"
echo
echo "== 3/3 verify"
"$MS" -Vm "$KIT/SHA256SUMS" -p "$D/c0f-minisign.pub"
( cd "$KIT" && bin/x86_64/sha256sum -c --quiet SHA256SUMS ) && echo "all kit files match SHA256SUMS"
echo
echo "Public key (also write it in the SOP):"; tail -n 1 "$D/c0f-minisign.pub"
# run as root: give the files back to the owner of the build tree / key folder
if [ "$(id -u)" = 0 ]; then chown "$(stat -c %u:%g "$KIT")" "$KIT/minisign.pub" "$KIT/SHA256SUMS" "$KIT/SHA256SUMS.minisig"
  chown "$(stat -c %u:%g "$D")" "$D/c0f-minisign.pub" "$D/c0f-minisign.key"; fi
echo "DONE."
