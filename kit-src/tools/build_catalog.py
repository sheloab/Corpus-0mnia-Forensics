#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Compile catalog/*.cat (readable source) into catalog.tsv (what c0f.sh executes) and validate it.

Source format:
  @phase 300                      following items get order 300, 301, 302 ...
  [D04-001] CMD kit 60            id, type (CMD|COPY|FUNC|DERIVED), tool (kit|server|kit-then-server|mixed), timeout seconds
  cmd: ps -eo ...                 command line (CMD), copy arguments (COPY) or function call (FUNC/DERIVED)
  out: processes/ps.txt           output file (CMD) or folder (FUNC); '-' for COPY / none
  req: has docker                 optional shell condition, item is NOT_APPLICABLE when false
  opt: RAM                        optional --no-xxx option name that disables the item
  purpose/expect/empty/value/changes/sensitive/ref: text
"""
import sys, os, re, glob
COLS = ["id","domain","order","type","option","requires","tool","command_or_path","output_file","timeout",
        "purpose","expected_output","empty_means","forensic_value","changes_system","sensitive","reference"]
KEYS = {"cmd":"command_or_path","out":"output_file","req":"requires","opt":"option","purpose":"purpose","expect":"expected_output",
        "empty":"empty_means","value":"forensic_value","changes":"changes_system","sensitive":"sensitive","ref":"reference"}
def main(src, dst):
    items, errs, phase, cur = [], [], None, None
    files = sorted(glob.glob(os.path.join(src, "*.cat")))
    for fn in files:
        n = 0
        for ln, line in enumerate(open(fn, encoding="utf-8"), 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"): continue
            if "\t" in line: errs.append(f"{fn}:{ln}: TAB not allowed")
            m = re.match(r"@phase\s+(\d+)$", line)
            if m: phase, n = int(m.group(1)), 0; continue
            m = re.match(r"\[(D\d\d-\d\d\d)\]\s+(CMD|COPY|FUNC|DERIVED)\s+(kit|server|kit-then-server|mixed)\s+(\d+)$", line)
            if m:
                if phase is None: errs.append(f"{fn}:{ln}: item before @phase")
                cur = {c: "-" for c in COLS}
                cur.update(id=m.group(1), domain=m.group(1)[:3], type=m.group(2), tool=m.group(3), timeout=m.group(4),
                           order=str((phase or 0)*10 + n), changes_system="no", sensitive="no", _src=f"{fn}:{ln}")
                n += 1; items.append(cur); continue
            m = re.match(r"(\w+):\s?(.*)$", line)
            if m and cur is not None and m.group(1) in KEYS:
                k = KEYS[m.group(1)]; v = m.group(2).strip()
                if cur[k] != "-" and not (k in ("changes_system", "sensitive") and cur[k] == "no"):
                    errs.append(f"{fn}:{ln}: duplicate key {m.group(1)} in {cur['id']}")
                cur[k] = v if v else "-"
                continue
            if cur is not None and line.startswith("  "):   # continuation of previous text field
                errs.append(f"{fn}:{ln}: continuation lines not supported"); continue
            errs.append(f"{fn}:{ln}: cannot parse: {line[:60]}")
    ids = {}
    for it in items:
        if it["id"] in ids: errs.append(f"duplicate id {it['id']} ({it['_src']} and {ids[it['id']]})")
        ids[it["id"]] = it["_src"]
        for k in ("command_or_path","purpose","expected_output","empty_means","forensic_value","reference"):
            if it[k] in ("", "-"): errs.append(f"{it['id']} ({it['_src']}): missing {k}")
        if it["type"] in ("CMD",) and it["output_file"] in ("", "-"): errs.append(f"{it['id']}: CMD needs out:")
        if it["type"] == "COPY" and it["output_file"] != "-": errs.append(f"{it['id']}: COPY must not have out:")
        for k in COLS:
            if it[k] == "": it[k] = "-"
            if "\t" in it[k]: errs.append(f"{it['id']}: tab in {k}")
    outs = {}
    for it in items:
        if it["output_file"] != "-":
            key = (it["domain"], it["output_file"])
            if key in outs: errs.append(f"{it['id']}: output {key} also used by {outs[key]}")
            outs[key] = it["id"]
    if errs:
        print("\n".join(errs), file=sys.stderr); sys.exit(1)
    # internal design-document references are not shipped
    for it in items:
        refs = [r.strip() for r in it["reference"].split(";") if r.strip() and not r.strip().startswith("draft") and r.strip() != "os-profile.tsv"]
        it["reference"] = "; ".join(refs) if refs else "C0F design"
    items.sort(key=lambda x: (int(x["order"]), x["id"]))
    with open(dst, "w", encoding="utf-8") as f:
        f.write("\t".join(COLS) + "\n")
        for it in items: f.write("\t".join(it[c] for c in COLS) + "\n")
    doms = {}
    for it in items: doms[it["domain"]] = doms.get(it["domain"], 0) + 1
    print(f"catalog: {len(items)} items -> {dst}"); print("per domain: " + ", ".join(f"{k}:{v}" for k, v in sorted(doms.items())))
if __name__ == "__main__": main(sys.argv[1], sys.argv[2])
