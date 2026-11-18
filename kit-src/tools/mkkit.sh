#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Assemble the non-binary parts of C0F-KIT from kit-src (bin/ and share/ come from kit/assemble.sh).
set -eu
S=$(cd "$(dirname "$0")/.." && pwd); K=${1:-$(cd "$S/.." && pwd)/kit/C0F-KIT}; V=$(cat "$S/VERSION")
export PYTHONDONTWRITEBYTECODE=1
python3 "$S/tools/build_catalog.py" "$S/catalog" "$K/catalog.tsv"
python3 "$S/tools/build_osprofile.py" "$K/os-profile.tsv"
mkdir -p "$K/lib"
{ for f in "$S"/lib-src/*.sh; do cat "$f"; done; } > "$K/lib/c0f-lib.sh"
cp "$S/lib-srv" "$K/lib/srv"
python3 - "$S" "$K" "$V" <<'PY'
import sys
S,K,V=sys.argv[1:4]
wide=open(f"{S}/banner-wide.txt").read().rstrip("\n"); narrow=open(f"{S}/banner-narrow.txt").read().rstrip("\n")
body=open(f"{S}/c0f.sh.in").read().replace("@@VERSION@@",V).replace("@@BANNER_WIDE@@",wide).replace("@@BANNER_NARROW@@",narrow)
head="#!/bin/sh\n" + "\n".join("# "+l for l in wide.split("\n")) + "\n"
open(f"{K}/c0f.sh","w").write(head+body)
PY
cp "$S/c0f" "$K/c0f"
mkdir -p "$K/LICENSES"; cp "$S"/LICENSES/* "$K/LICENSES/"; cp "$S/c0f-license.txt" "$K/LICENSES/C0F.txt"; cp "$S/VENDOR-BINARIES.txt" "$K/LICENSES/VENDOR-BINARIES.txt"
mkdir -p "$K/docs"; [ -d "$S/docs" ] && cp "$S"/docs/* "$K/docs/"
python3 "$S/tools/gen_reference.py" "$K" "$V"
python3 "$S/tools/gen_readme.py" "$K" "$V"
"$S/tools/gen_buildinfo.sh" "$K" "$V"
chmod 755 "$K/c0f" "$K/c0f.sh" "$K/lib/srv"; chmod 644 "$K"/docs/* "$K/README.txt" "$K/BUILDINFO.txt" "$K/LICENSES"/* "$K/catalog.tsv" "$K/os-profile.tsv" "$K/lib/c0f-lib.sh"
# syntax check with the kit's own BusyBox shell
"$K/bin/x86_64/busybox" sh -n "$K/c0f.sh" && "$K/bin/x86_64/busybox" sh -n "$K/lib/c0f-lib.sh" && "$K/bin/x86_64/busybox" sh -n "$K/c0f" && echo "syntax OK (busybox ash)"
