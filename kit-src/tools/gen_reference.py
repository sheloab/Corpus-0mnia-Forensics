#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Write docs/REFERENCE.md: every catalog item with what it collects, how (command / function / copied paths),
which kit tools and which server programs it can use, output and time limit; then every kit tool with the items
that use it. Generated from catalog.tsv + lib-src, so it always matches the kit.
usage: gen_reference.py KITDIR VERSION"""
import csv, glob, os, re, sys

K, V = sys.argv[1], sys.argv[2]
S = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(S, "tools"))
from components import components

csv.field_size_limit(10**9)
rows = list(csv.DictReader(open(os.path.join(K, "catalog.tsv")), delimiter="\t", quoting=csv.QUOTE_NONE))
DOM = {"D01": ("01_system", "System identity and state"), "D02": ("02_time", "Time and time zone"),
       "D03": ("03_memory", "Memory"), "D04": ("04_processes", "Processes"), "D05": ("05_network", "Network"),
       "D06": ("06_firewall_hardening", "Firewall and hardening"), "D07": ("07_accounts_auth", "Accounts and authentication"),
       "D08": ("08_persistence", "Persistence"), "D09": ("09_services", "Services"), "D10": ("10_software", "Software and packages"),
       "D11": ("11_filesystem_storage", "Filesystem and storage"), "D12": ("12_logs", "Logs"), "D13": ("13_web_servers", "Web servers"),
       "D14": ("14_databases", "Databases"), "D15": ("15_mail", "Mail"), "D16": ("16_applications", "User applications"),
       "D17": ("17_desktop_gui", "Desktop / GUI"), "D18": ("18_containers", "Containers"), "D19": ("19_kubernetes", "Kubernetes"),
       "D20": ("20_virtualization", "Virtualization"), "D21": ("21_cloud_agents", "Cloud agents"),
       "D22": ("22_security_tools", "Security tools"), "D23": ("23_kernel_rootkit", "Kernel and rootkit checks")}
OPT = {"RAM": "--no-ram", "SWAP": "--no-swap", "PCAP": "--no-pcap", "TIMELINE": "--no-timeline", "E2IMAGE": "--no-e2image",
       "CEXPORT": "--no-container-export", "DBBINLOG": "--no-db-binlogs", "DBWAL": "--no-db-wal", "DBDATA": "--no-db-data",
       "PDUMP": "--no-process-dumps", "SCREENSHOT": "--no-screenshot", "CLIPBOARD": "--no-clipboard"}

# lib functions: name -> body (without comment lines)
FUN = {}
for f in sorted(glob.glob(os.path.join(S, "lib-src", "*.sh"))):
    name, body = None, []
    for line in open(f):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) *\{", line)
        if m and name is None:
            name, body = m.group(1), [line[m.end():]]
            if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
                FUN[name] = "".join(body); name = None
            continue
        if name is not None:
            if line.startswith("}"):
                FUN[name] = "".join(body); name = None
            elif not line.lstrip().startswith("#"):
                body.append(line)

def expand(text, seen=None):
    """text plus the bodies of every lib function it calls (recursively)"""
    seen = seen if seen is not None else set()
    out = [text]
    for fn in FUN:
        if fn not in seen and re.search(r"(?<![\w$.-])" + re.escape(fn) + r"(?![\w-])", text):
            seen.add(fn); out.append(expand(FUN[fn], seen))
    return "\n".join(out)

BIN = sorted(os.path.basename(p) for p in glob.glob(os.path.join(K, "bin", "x86_64", "*")) if os.path.isfile(p))
BIN += ["chkrootkit"]
BIN = sorted(set(BIN) - {"busybox", "strings-static"})
SKIP_WORDS = {"file", "test", "date", "printf", "env", "id", "ls", "cat", "cut", "sort", "uniq", "wc", "tr", "head", "tail",
              "tee", "touch", "mkdir", "dirname", "basename", "readlink", "realpath", "stat", "cp", "dd", "du", "df", "find",
              "xargs", "uname", "whoami", "chmod", "chown", "split", "sha1sum", "sha256sum", "sha512sum", "md5sum", "b2sum",
              "base64", "nice", "nohup", "timeout", "setsid", "flock", "free", "uptime", "tar", "mkdir", "printf", "pwdx"}

def tools_in(text):
    t = re.sub(r"\bsrv\s+\S+", " ", text)          # server programs are listed separately
    found = []
    for b in BIN:
        if re.search(r"(?<![\w./$-])" + re.escape(b) + r"(?![\w-])", t):
            found.append(b)
    return found

def srv_in(text):
    return sorted(set(re.findall(r"\b(?:srv|has)\s+([A-Za-z0-9_.+-]+)", text)) - {"-p", "--"})

def esc(s):
    return s.replace("|", "\\|").replace("\n", " ")

def short(s, n=170):
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n - 1] + "…"

def hms(t):
    t = int(t)
    return f"{t}s" if t < 60 else (f"{t // 60} min" if t < 3600 else f"{t / 3600:g} h")

use = {}
srvuse = {}
o = []
o.append(f"# C0F {V} - collection reference\n")
o.append("Generated from `catalog.tsv` and the collection functions of this kit, so it always matches the kit. "
         "Every item runs as its own process with a time limit; a failing item is reported and the run continues.\n")
o.append("**How** shows the command (CMD), the files/folders copied with `c0f-copy` (COPY), or the collection function "
         "(FUNC, in `lib/c0f-lib.sh`). **Kit tools** are the trusted static programs from `bin/<arch>/` that the item uses "
         "(shell built-ins and BusyBox/coreutils basics such as `cat`, `find`, `sort` are not listed). **Server programs** "
         "are used only when they exist on the examined system (e.g. `rpm`, `systemctl`); each use is recorded as "
         "`UNTRUSTED_TOOL` in `tools-used.csv`. **Limit** is the default time limit (`--timeout-factor N` multiplies it; "
         "in an interactive run you are asked whether to wait longer).\n")
o.append("Status of every item after a run: `99_custody/items.tsv`, `report.txt`, `failures.csv`, `not-collected.csv`.\n")
o.append("## Domains\n\n| Domain | Output folder | Items |\n|---|---|---|")
cnt = {}
for r in rows:
    cnt[r["domain"]] = cnt.get(r["domain"], 0) + 1
for d in sorted(DOM):
    o.append(f"| [{d} {DOM[d][1]}](#{d.lower()}-{DOM[d][1].lower().replace(' / ', '--').replace(' ', '-')}) | `{DOM[d][0]}/` | {cnt.get(d, 0)} |")
o.append(f"\nTotal: {len(rows)} items.\n")

for d in sorted(DOM):
    items = sorted([r for r in rows if r["domain"] == d], key=lambda r: r["id"])
    if not items:
        continue
    o.append(f"## {d} {DOM[d][1]}\n\nOutput folder `{DOM[d][0]}/`\n")
    o.append("| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |")
    o.append("|---|---|---|---|---|---|---|")
    for r in items:
        typ, cmd = r["type"], r["command_or_path"]
        if typ == "FUNC" or typ == "DERIVED":
            how = f"{typ} `{esc(cmd.split()[0])}`"
        elif typ == "COPY":
            how = "COPY " + esc(short(" ".join(x for x in cmd.split() if not x.startswith("-")), 150))
        else:
            how = f"CMD `{esc(short(cmd))}`"
        full = expand(cmd)
        kt = tools_in(full); st = srv_in(full)
        for b in kt:
            use.setdefault(b, []).append(r["id"])
        for b in st:
            srvuse.setdefault(b, []).append(r["id"])
        flags = []
        if r["option"] not in ("", "-"):
            flags.append(f"off with `{OPT.get(r['option'], r['option'])}`")
        if r["sensitive"] == "yes":
            flags.append("sensitive")
        if r["changes_system"].strip().lower() not in ("", "-", "no", "none"):
            flags.append("changes: " + esc(short(r["changes_system"], 80)))
        what = esc(short(r["purpose"], 220)) + (f" *({'; '.join(flags)})*" if flags else "")
        o.append(f"| {r['id']} | {what} | {how} | {', '.join(f'`{b}`' for b in kt if b not in SKIP_WORDS) or '-'} | "
                 f"{', '.join(st) or '-'} | `{esc(r['output_file'])}` | {hms(r['timeout'])} |")
    o.append("")

o.append("## Kit tools and the items that use them\n")
o.append("All tools are statically linked and verified against the signed `SHA256SUMS` before use. "
         "BusyBox provides the shell (`c0f.sh`) and basic applets (`awk`, `sed`, `grep`, ...).\n")
o.append("| Component | Version | Programs in `bin/<arch>/` | License |\n|---|---|---|---|")
for n, ver, files, lic, src, how in components(V):
    o.append(f"| {esc(n)} | {esc(ver)} | {esc(files)} | {esc(lic)} |")
o.append("\n| Tool | Used by items |\n|---|---|")
for b in sorted(use):
    ids = sorted(set(use[b]))
    o.append(f"| `{b}` | {len(ids)}: {', '.join(ids)} |")
unused = [b for b in BIN if b not in use and b not in SKIP_WORDS]
if unused:
    o.append(f"\nAlso in the kit (support programs, used by the collector itself or inside other tools): "
             f"{', '.join(f'`{b}`' for b in unused)}.")
o.append("\n## Server programs C0F may call\n")
o.append("Only when present on the examined system. They are not trusted: every use is logged per item and listed "
         "in `tools-used.csv` (with SHA-256); a crash is reported as `SERVER_TOOL_CRASHED`.\n")
o.append("| Program | Items |\n|---|---|")
for b in sorted(srvuse):
    ids = sorted(set(srvuse[b]))
    o.append(f"| `{b}` | {', '.join(ids)} |")
os.makedirs(os.path.join(K, "docs"), exist_ok=True)
open(os.path.join(K, "docs", "REFERENCE.md"), "w").write("\n".join(o) + "\n")
print(f"REFERENCE.md: {len(rows)} items, {len(use)} kit tools, {len(srvuse)} server programs")
