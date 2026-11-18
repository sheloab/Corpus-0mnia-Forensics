#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# write SHA256SUMS for C0F-KIT (every file except the sums, signature and per-host output folders) and sign it
set -eu
K=${1:?kit}; KEY=${2:?secret key}; TC=${3:-C0F kit}
MSD=$(cd "$(dirname "$0")/.." && pwd)
cd "$K"
find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.minisig | sed 's|^\./||' | grep -vE '^[^/]+/(\.work-|.*_[0-9]{2}-[A-Z][a-z]{2}-[0-9]{4}_)|^\.c0f' | grep -E '^(c0f|c0f\.sh|catalog\.tsv|os-profile\.tsv|README\.txt|BUILDINFO\.txt|minisign\.pub|lib/|bin/|share/|LICENSES/|docs/)' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
MS=$MSD/tools/minisign-linux/x86_64/minisign
if [ "${C0F_SIGN_INTERACTIVE:-0}" = 1 ]; then "$MS" -Sm SHA256SUMS -s "$KEY" -t "$TC"   # password-protected key: prompt visible
else "$MS" -Sm SHA256SUMS -s "$KEY" -t "$TC" -W >/dev/null 2>&1 || "$MS" -Sm SHA256SUMS -s "$KEY" -t "$TC"; fi
echo "SHA256SUMS: $(wc -l < SHA256SUMS) files"
