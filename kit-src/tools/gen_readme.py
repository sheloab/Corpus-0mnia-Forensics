#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Generate C0F-KIT/README.txt from catalog.tsv, os-profile.tsv and the component list. Usage: gen_readme.py KITDIR VERSION"""
import sys, csv, textwrap, os, re
K, V = sys.argv[1], sys.argv[2]
W = 100
def wrap(t, ind=0, first=None):
    p = " " * ind
    return textwrap.fill(t, W, initial_indent=(first if first is not None else p), subsequent_indent=p, break_long_words=False, break_on_hyphens=False)
def h1(t): return f"\n{'=' * W}\n{t}\n{'=' * W}\n"
def h2(t): return f"\n{t}\n{'-' * len(t)}\n"

rows = list(csv.DictReader(open(f"{K}/catalog.tsv", encoding="utf-8"), delimiter="\t"))
prof = list(csv.DictReader(open(f"{K}/os-profile.tsv", encoding="utf-8"), delimiter="\t"))
banner = open(os.path.join(os.path.dirname(__file__), "..", "banner-narrow.txt")).read().rstrip("\n")

DOM = {
 "D01": ("01_system", "System identity and hardware",
   "Identifies exactly which machine, OS release and kernel the evidence comes from (serials, UUIDs, machine-id) and whether it is a VM, container or cloud instance.",
   "Firmware/BIOS implants and hypervisor-level data are outside the reach of a live collector."),
 "D02": ("02_time", "Time, time zone and clock synchronisation",
   "Every later timestamp is interpreted with these values. Wrong time zone, RTC in local time, disabled NTP or deliberate clock changes break timelines.",
   "The true offset of the server clock needs the examiner's trusted clock (asked at start and end)."),
 "D03": ("03_memory", "Memory",
   "RAM is the most volatile evidence (RFC 3227). It holds running malware, keys, unsaved commands and kernel rootkits.",
   "No RAM image on armv7 (no AVML build); kernel lockdown or Yama ptrace_scope=3 can refuse memory access."),
 "D04": ("04_processes", "Processes",
   "Shows what runs now, as whom, since when, from which executable, with which open files and namespaces.",
   "A kernel rootkit can hide processes from every user-space tool; D23 cross-checks reduce but cannot remove this risk."),
 "D05": ("05_network", "Network",
   "Live connections, listeners and the process behind each; routing, DNS and tunnels; a short packet capture.",
   "Past traffic is not stored on the server (ask firewall/NetFlow/SIEM)."),
 "D06": ("06_firewall_hardening", "Firewall and hardening",
   "Runtime and persistent firewall rules of every backend, fail2ban/CrowdSec, SELinux/AppArmor and kernel parameters.",
   "Network devices in front of the server are out of scope."),
 "D07": ("07_accounts_auth", "Accounts, authentication and login history",
   "Who can log in, who is admin, who logged in from where, which SSH keys exist and whether they have a passphrase.",
   "Accounts that exist only in a directory (LDAP/AD) are read through the server's NSS when available; login records rotated away are gone."),
 "D08": ("08_persistence", "Persistence",
   "Every place where code is started automatically: cron/at, systemd units and timers, init scripts, shell start-up files, preload, modules, udev, hooks.",
   "Persistence in firmware or in network devices is out of scope."),
 "D09": ("09_services", "Services and daemons",
   "Which daemons run, since when, which binary, when the unit was installed/enabled and whether a package owns it.",
   "Without systemd the start time comes from the process; install time of init scripts is the file time."),
 "D10": ("10_software", "Software",
   "What is installed, when, from which repository or local file, what was removed, and whether installed files were modified.",
   "Alpine keeps no install/remove log; software installed by hand leaves no package record (see unpackaged executables)."),
 "D11": ("11_filesystem_storage", "Filesystem and storage",
   "Mounts, LVM/RAID/LUKS, filesystem parameters, SUID/capabilities, hidden files, recent changes, the full timeline and filesystem metadata images (the Linux equivalent of the NTFS $MFT).",
   "Content of deleted files needs a full disk image; metadata images of busy filesystems can be slightly inconsistent."),
 "D12": ("12_logs", "Logs",
   "All of /var/log (no size limit), journal files and text export, logs outside /var/log, audit and accounting, and checks for log tampering.",
   "Logs already rotated away or deleted can only come from a SIEM or remote syslog (their destinations are recorded)."),
 "D13": ("13_web_servers", "Web servers",
   "Web server configuration, real log locations from the configuration, document roots with hashes and copies of recently changed scripts (webshells).",
   "Logs disabled in the configuration were never written."),
 "D14": ("14_databases", "Databases",
   "Database configuration, error/general/slow/audit logs, binary logs/WAL, client histories. C0F never logs into a database.",
   "Audit trails stored in database tables, oplogs and user tables need a database login (not done)."),
 "D15": ("15_mail", "Mail",
   "Mail server configuration, local mailboxes, queues and forwarding rules.",
   "Mail already delivered off the host."),
 "D16": ("16_applications", "Applications and user artefacts",
   "Shell histories (with tampering checks), cloud/registry credentials, remote access and tunnelling tools, IDE remote servers, terminal multiplexer buffers.",
   "Commands typed in a shell that is still open are not yet written to disk (D03-011 recovers some from memory)."),
 "D17": ("17_desktop_gui", "Desktop and GUI",
   "Clipboard, window list and screenshots of X11 displays, browser and desktop artefacts.",
   "Wayland sessions usually refuse screenshots/clipboard reads from other processes."),
 "D18": ("18_containers", "Containers",
   "State, logs, changes, images and build files of Docker/Podman/containerd/CRI-O/LXC containers, and the network and key files inside each container read from the host.",
   "Containers started with --rm that already exited leave only events and journal traces."),
 "D19": ("19_kubernetes", "Kubernetes",
   "Node configuration, pod logs, node services and (with a local admin kubeconfig) a read-only cluster export including RBAC, webhooks and pod logs.",
   "Managed control planes (EKS/GKE/AKS) keep audit logs at the cloud provider."),
 "D20": ("20_virtualization", "Virtualization",
   "Virtual machines hosted on this server (libvirt, Proxmox, VirtualBox) and their configuration.",
   "Hypervisor-level introspection of THIS machine (when it is a VM) is done by the infrastructure team."),
 "D21": ("21_cloud_agents", "Cloud agents",
   "Cloud-init and cloud agent state and logs, provider identifiers read from local files (no metadata service calls).",
   "Control-plane logs (CloudTrail, activity logs) are at the provider."),
 "D22": ("22_security_tools", "Security tools",
   "EDR/AV/HIDS agents, their status and logs, and file integrity databases.",
   "Cloud consoles of the security products are out of scope."),
 "D23": ("23_kernel_rootkit", "Kernel and rootkit checks",
   "Kernel taint, modules, eBPF/tracing, hidden processes/ports/files found by comparing independent methods, and chkrootkit.",
   "An active kernel rootkit can lie to every tool on the running system; the RAM image (D03-001) allows offline verification."),
}
REFS = {
 "RFC3227": "RFC 3227 - Guidelines for Evidence Collection and Archiving (IETF, 2002) https://www.rfc-editor.org/rfc/rfc3227",
 "NIST800-86": "NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response https://csrc.nist.gov/pubs/sp/800/86/final",
 "SANS-FOR577": "SANS FOR577 - Linux Incident Response and Threat Hunting (course material), https://www.sans.org",
 "ISO27037": "ISO/IEC 27037:2012 - Guidelines for identification, collection, acquisition and preservation of digital evidence https://www.iso.org/standard/44381.html",
}
def ref_text(r):
    out = []
    for t in [x.strip() for x in r.split(";") if x.strip()]:
        if t.startswith("UAC:"): out.append(f"UAC artifact '{t[4:]}' (https://github.com/tclahr/uac)")
        elif t.startswith("man:"): out.append(f"man page {t[4:]}")
        else: out.append(t)
    return "; ".join(out)

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from components import components
COMP = components(V)

o = []
o.append(banner)
o.append(f"\n  Corpus-0mnia Forensics (C0F) {V} - README\n  Linux live-response evidence collector: one script + a trusted, signed static toolkit.\n")
o.append("CONTENTS\n  1 What this is          5 How to run             9 After collection        13 Version history\n  2 Before you start      6 What it collects      10 Troubleshooting\n  3 Kit contents          7 What it changes       11 Standards and references\n  4 Verify the kit        8 Output                12 Sources and licenses")

o.append(h1("1. WHAT THIS IS"))
o.append(wrap("C0F collects evidence from a RUNNING Linux system (live response) and packs it into one encrypted 7-Zip archive with a manifest (SHA-256 + MD5 of every file), a report of what was and was not collected with the reason, and a chain-of-custody record. It runs on any Linux distribution and version on x86_64, aarch64 and armv7, including minimal installations: every generic tool comes from this kit (static binaries), so the result does not depend on (possibly tampered) programs of the examined server. Programs that exist only when a product is installed on the server (systemctl, rpm, dpkg, docker daemon tools, nginx -T, ...) are taken from the server, clearly marked UNTRUSTED_TOOL, and their hashes are recorded."))
o.append("")
o.append(wrap("Use it for incident response triage and evidence preservation on servers, VMs, cloud instances, container hosts and Kubernetes nodes. It is NOT a replacement for a full disk image (deleted file content) and it cannot defeat an active kernel rootkit on its own (the RAM image allows offline verification)."))

o.append(h1("2. BEFORE YOU START"))
for t in ["Get written authorization from the system owner / incident lead. The archive contains password hashes, private keys, tokens, process environments and personal data.",
          "Tell the SOC/EDR team: memory dumps, packet capture and many reads of credential files can raise alerts or be blocked (fapolicyd, SELinux, EDR).",
          "Prefer running the kit from external media (USB disk) or a network share so the evidence is not written to the examined disk. If the kit folder is read-only, give --out DIR.",
          "Check free space: the start screen shows a rough estimate. A RAM image is as large as the installed RAM; about twice the collected size is needed while the archive is created.",
          "Have a trusted clock ready (phone/GPS). C0F asks for the time at start and end to measure the server's clock offset.",
          "Verify the kit on YOUR workstation first (section 4) and compare the public key and SHA256SUMS hash with your SOP."]:
    o.append(wrap(t, 4, "  - "))

o.append(h1("3. KIT CONTENTS"))
o.append("""  C0F-KIT/
    c0f                 launcher: finds the kit BusyBox that runs on this CPU and starts c0f.sh with it
    c0f.sh              the collector (BusyBox ash script)
    catalog.tsv         every artefact C0F collects: one row per item (this README section 6 is generated from it)
    os-profile.tsv      what each OS family/version is expected to have (EXPECTED_BUT_MISSING checks)
    lib/c0f-lib.sh      functions used by catalog items;  lib/srv  runs a SERVER program (logged as UNTRUSTED_TOOL)
    bin/x86_64/ bin/aarch64/ bin/armv7/   static tools per architecture (see section 12)
    share/magic.mgc     database for 'file'
    SHA256SUMS          SHA-256 of every kit file;  SHA256SUMS.minisig  its minisign signature;  minisign.pub
    BUILDINFO.txt       how and from what the kit was built, test results;   LICENSES/   license texts
    docs/               GUIDE.md (step by step, messages, durations), REFERENCE.md (every item + tools), VERIFY.md
    README.txt          this file""")
o.append("")
o.append(wrap("C0F's own helpers (source included in the build records): c0f-copy (evidence copy with O_NOATIME, statx metadata incl. birth time recorded BEFORE reading, SHA-256 of the bytes read, change detection, sparse-aware, FAT32-safe splitting, metadata-only and digest modes, bodyfile output); c0f-logins (utmp/wtmp/btmp, lastlog, faillog parser independent of the C library, with anomaly flags); c0f-memdump (process memory through /proc/PID/mem); c0f-sshkey (SSH key inventory and fingerprints without ssh-keygen, never prints secret material); c0f-x11 (X11 clipboard, window list, screenshot without Xlib).", 4, "  "))

o.append(h1("4. VERIFY THE KIT"))
o.append("""  Trust comes from OUTSIDE the kit. Anyone may build and sign their own copy of C0F (open license), and a
  replaced kit can carry its own minisign.pub and an altered c0f.sh. Only the official C0F public key, taken from
  your SOP or the official C0F repository (NOT from this kit), proves that a kit is an official release:

      official public key:  RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p   (key id 3DB6F4F714FD95C5)

  A. Before use, on your own workstation (never on the server you examine):
     Release download: verify the release checksum list, then the archive.
       Linux/macOS:  minisign -Vm RELEASE-SHA256SUMS.txt -P <official public key>
                     sha256sum -c --ignore-missing RELEASE-SHA256SUMS.txt
       Windows:      minisign.exe -Vm RELEASE-SHA256SUMS.txt -P <official public key>
                     certutil -hashfile C0F-<version>.tar.gz SHA256     (compare with RELEASE-SHA256SUMS.txt)
     Extracted kit (or a kit copied from a colleague):
       minisign -Vm SHA256SUMS -P <official public key>   -> "Signature and comment signature verified"
                                                             trusted comment "C0F <version> - official release"
       sha256sum -c SHA256SUMS                            -> every line "OK"
     Use a minisign you trust (from your OS packages or https://github.com/jedisct1/minisign), not the one in bin/.
     Record the SHA-256 of SHA256SUMS in your case notes.

  B. Automatically at every start: C0F checks the signature with the minisign.pub inside the kit and the SHA-256
     of every file, and prints the public key it used. If that key is not the official key above, the kit is NOT
     an official C0F release (it may be a legitimate private build or a tampered one): stop and investigate.
     This self-check catches damaged or partly modified kits; it cannot replace step A, because a fully replaced
     kit controls its own check.

  What happens on the server when something does not match (decision B):
    - signature fails, or a CORE file is modified/missing (c0f, c0f.sh, catalog.tsv, os-profile.tsv, lib/*,
      busybox, minisign, sha256sum, timeout, c0f-copy, date)  -> STOP before collecting (exit code 3); a file
      <HOSTNAME>/C0F-KIT-VERIFY-FAILED_<time>.txt is written. Override only with
      --force-untrusted-kit "<reason>"  (integrity status COMPROMISED, reason recorded in the custody file)
    - other kit binary modified -> NOT executed; the server's program is used instead (QUESTIONABLE)
    - other kit binary missing  -> server's program instead (DEGRADED)
    - foreign file in bin/<arch>/ -> never executed, copied into the evidence (QUESTIONABLE)
    - the kit is re-hashed at the end; a change during the run is reported as KIT CHANGED DURING RUN
  Integrity levels: VERIFIED < DEGRADED < QUESTIONABLE < COMPROMISED (shown on the first line of every report).""")

o.append(h1("5. HOW TO RUN"))
o.append("""  1. Mount/copy the kit on the server (keep the folder structure). The media must not be mounted noexec.
  2. Start it as root:   sudo ./c0f            (no /bin/sh on the host?  ./bin/x86_64/busybox sh ./c0f.sh)
     If not started as root, C0F restarts itself with sudo; without root it stops.
  3. Answer the prompts, in this order (Enter accepts the value in [brackets] or skips):
       Save output to [<kit folder>/<HOSTNAME>]   Case / ticket number   Examiner name
       Current time from a TRUSTED clock (UTC)    Examiner note
     Read the warning screen and type YES (anything else aborts, exit code 2).
  4. Wait. Progress is shown per domain; every failure is a WARN line and the run continues.
     Time limits: every item has one (10 s to 8 h). When an item reaches it in an interactive run, C0F asks:
       press Enter = stop the item and keep its partial output, or type minutes (1-1440) to wait longer;
       no answer within 2 minutes = stop. --timeout-factor N multiplies all limits; --no-timeout-prompt never asks.
  5. At the end: trusted time again and a closing note (Enter skips), then note the archive path, SHA-256 and
     password shown on screen (section 8).
  Step-by-step guide with real screen output, error messages and duration estimates: docs/GUIDE.md.
  What every item collects, with the command/tool it uses: docs/REFERENCE.md.

  Non-interactive:  sudo ./c0f --yes --case IR-2026-001 --examiner "J. Doe" --out /mnt/usb/evidence

  Options""")
o.append(textwrap.indent("""--out DIR                 output folder (default: <kit folder>/<HOSTNAME>)
--work DIR                working folder (default: inside the output folder)
--case ID / --examiner NAME    case details (asked when missing)
--yes                     no questions (needs --case and --examiner)
--timeout-factor N        multiply every item time limit by N (1-100)
--no-timeout-prompt       never ask at a time limit (stop the item, keep partial output)
--since DAYS              window for 'recently changed' summaries (default 30)
--password TEXT / --password-prompt    archive password (default: short hostname)
--pcap-seconds N          packet capture length (default 60)
--kubeconfig FILE         kubeconfig for cluster-level Kubernetes collection
--no-ram --no-swap --no-pcap --no-timeline --no-e2image --no-container-export
--no-db-binlogs --no-db-wal --no-db-data --no-process-dumps --no-screenshot --no-clipboard
                          turn off large or intrusive parts (all ON by default)
--dry-run                 list what would be collected on this host, collect nothing
--self-test               verify the kit and test every kit tool on this host, then exit
--force-untrusted-kit "REASON"   continue although core kit verification failed (COMPROMISED)
--keep-work               keep the working folder after the archive is verified
--no-banner, --version, --help""", "      "))
o.append("""
  Exit codes: 0 complete, 1 partial (some items failed), 2 aborted/interrupted, 3 kit verification failed.
  Ctrl+C stops the collection: what was collected is still listed, hashed and archived (status INTERRUPTED).
  A dropped SSH session does not stop the run (SIGHUP ignored); follow it in <work>/tmp/collector.log.""")

o.append(h1("6. WHAT IT COLLECTS"))
o.append(wrap("Collection order follows volatility (RFC 3227), not the folder order: clock and identity, RAM, processes, network, sessions, logs (copied early so our own activity cannot rotate them away), then configuration, persistence, services, software, firewall, storage, applications, desktop, containers, Kubernetes, virtualization, cloud, security tools, kernel/rootkit checks, and finally the heavy parts (timeline, metadata images, container exports, package verification).", 2, "  "))
o.append("")
o.append(wrap("Each item below shows: ID, type (CMD = runs a command, output captured; COPY = files copied with metadata; FUNC = a collection procedure that may produce many files; DERIVED = a table built by C0F), tool (kit / server / mixed), the command or paths, and what to expect. 'Empty means' explains whether an empty or missing result is normal or suspicious. Items marked SENSITIVE contain secrets or personal data. In COPY paths, -R means recursive and -x means 'stay on one filesystem'.", 2, "  "))
o.append("")
o.append(wrap(f"Totals: {len(rows)} catalog items in 23 domains. Most FUNC items collect many artefacts each (for example one per user, process, container or display).", 2, "  "))
for code in sorted(DOM):
    folder, title, why, cannot = DOM[code]
    items = sorted([r for r in rows if r["domain"] == code], key=lambda r: r["id"])
    o.append(h2(f"{code}  {title}   (folder {folder}/, {len(items)} items)"))
    o.append(wrap("Why it matters: " + why, 2, "  "))
    o.append(wrap("Cannot be collected: " + cannot, 2, "  "))
    for r in items:
        o.append("")
        flags = []
        if r["sensitive"] == "yes": flags.append("SENSITIVE")
        if r["option"] != "-": flags.append(f"disable with --no-{r['option'].lower().replace('pdump','process-dumps').replace('cexport','container-export').replace('dbbinlog','db-binlogs').replace('dbwal','db-wal').replace('dbdata','db-data')}")
        o.append(f"  {r['id']}  {r['type']}/{r['tool']}  timeout {r['timeout']}s  output: {r['output_file'] if r['output_file']!='-' else ('files/' if r['type']=='COPY' else '-')}" + (f"  [{', '.join(flags)}]" if flags else ""))
        o.append(wrap(r["purpose"], 6))
        o.append(wrap(("Command: " if r["type"] in ("CMD",) else "Paths: " if r["type"] == "COPY" else "Procedure: ") + r["command_or_path"], 10, "      "))
        if r["requires"] != "-": o.append(wrap("Runs only when: " + r["requires"], 10, "      "))
        o.append(wrap("Expected: " + r["expected_output"], 10, "      "))
        o.append(wrap("Empty means: " + r["empty_means"], 10, "      "))
        o.append(wrap("Forensic value: " + r["forensic_value"], 10, "      "))
        if r["changes_system"] not in ("no", "-"): o.append(wrap("Changes on the system: " + r["changes_system"], 10, "      "))
        o.append(wrap("Reference: " + ref_text(r["reference"]), 10, "      "))

o.append(h2("OS profiles (os-profile.tsv)"))
o.append(wrap("C0F reads /etc/os-release (or older release files) and selects a profile. The profile does NOT limit what is collected: every candidate location is checked on every system. It adds expectations: a command the profile requires but that is missing is reported as EXPECTED_BUT_MISSING (minimal install, or removed/replaced tools), and default-install items that are absent are listed as information in 01_system/os-profile.txt.", 2, "  "))
o.append("")
o.append("  profile              matches ID / ID_LIKE                     versions      pkg     must have")
for p in prof:
    vr = f"{p['version_min']}-{p['version_max']}" if p["version_min"] != "-" else "any"
    o.append(f"  {p['profile']:<20} {p['id_regex'][:40]:<40} {vr:<13} {p['package_manager']:<7} {p['expect_must']}")

o.append(h1("7. WHAT IT CHANGES ON THE SYSTEM"))
for t in ["Creates the output folder and files (and its working folder) on the chosen location. If that is the examined disk, free space is overwritten (less chance to recover deleted files) - recorded in the custody file.",
          "Adds log entries: sudo/su (if used to start it), auditd records of every program it runs, journal entries; logs are copied BEFORE the heavy part of the run to limit rotation effects.",
          "Reads many files: C0F's own copies use O_NOATIME so access times stay unchanged; programs from the server or other kit tools may still update access times on filesystems mounted with strictatime.",
          "Starts processes (visible to EDR), uses CPU and disk I/O (runs normally; heavy parts are last).",
          "Packet capture switches interfaces to promiscuous mode for its duration (default 60 s).",
          "Sends SIGUSR1 to systemd-resolved/dnsmasq when they run, which makes them write their DNS cache to the log.",
          "Clipboard reading creates one temporary InputOnly X11 window and asks the owning application for its data; it may create the standard atoms CLIPBOARD/TARGETS/TIMESTAMP/INCR/UTF8_STRING if missing.",
          "Kubernetes cluster-level reads are recorded in the API server audit log. tmux buffers are read through the user's tmux server.",
          "It does NOT install packages, change configuration, restart services, run commands inside containers (docker exec), log into databases or contact the internet (no metadata service calls, package tools in cache-only mode)."]:
    o.append(wrap(t, 4, "  - "))

o.append(h1("8. OUTPUT"))
o.append("""  <output folder>/
    <HOST>_<IP>_<DD-Mmm-YYYY>_<HH-MM-SS-sssss>_UTC<+hhmm>.7z           encrypted archive (AES-256, file names encrypted)
                                                                       on FAT32 split into .7z.001, .7z.002, ...
    <same name>.sha256        SHA-256 and MD5 of the archive (an archive cannot contain its own hash)
    <same name>.report.txt    readable report (also inside the archive)
    <same name>.custody.txt   chain-of-custody summary (also inside the archive)

  Archive password: the short hostname of the server (after sanitizing), shown on screen at the end and in the
  report - unless --password/--password-prompt was used. Open with 7-Zip (Windows), 7zz/7z (Linux/macOS);
  Windows Explorer cannot open AES-encrypted 7z archives.

  Inside the archive: one folder per domain (01_system ... 23_kernel_rootkit, 99_custody). Every folder exists
  even when nothing was found (empty folder = nothing there; the reason is in the manifest). COPY items keep the
  original path under <domain>/files/ (for example 12_logs/files/var/log/auth.log).

  99_custody/
    manifest.csv          one row per file: item, method (COPY/CAPTURE), source path or command, archive path, size,
                          SHA-256, MD5, SHA-256 of the bytes read from the source, original mtime/ctime/atime/birth
                          time, owner, mode, inode, time collected, status, reason, tool integrity; plus one row per
                          artefact that was looked for but not collected
    report.txt            summary; COLLECTED / NOT COLLECTED (reason) / FAILED (reason) lists
    chain-of-custody.txt  case, examiner, host identity, times, trusted clock, kit hashes, manifest hash, handover form
    failures.csv, not-collected.csv, items.tsv, tools-used.csv (kit tools + server programs used with SHA-256),
    kit-integrity.csv, kit-selftest.csv, collector.log (every step with UTC time, exit code, duration)

  Status values:  OK  EMPTY  NOT FOUND  SKIPPED  FAILED  TIMEOUT  DENIED   (sub-results may show PARTIAL)
  Reason codes:   NOT_FOUND  CMD_MISSING  EXPECTED_BUT_MISSING  NOT_APPLICABLE  DISABLED_BY_OPTION  PERMISSION_DENIED
                  BLOCKED_BY_POLICY  TIMEOUT  EXIT_NONZERO  EMPTY  UNSUPPORTED_ARCH  KERNEL_TOO_OLD  NO_SPACE
                  CHANGED_DURING_COPY  UNTRUSTED_TOOL  INTERRUPTED  KIT_TOOL_MODIFIED  KIT_TOOL_MISSING
                  SERVER_TOOL_CRASHED (a server program crashed: SIGSEGV/SIGILL/SIGBUS/...; partial output kept;
                  on a server whose own tools crash, suspect tampering, damaged files or an incompatible kernel)
                  TOOL_CRASHED (the item's command itself crashed)
  Times: all timestamps in manifest, logs and custody files are UTC (ISO 8601); local time with offset is shown
  next to them where useful.""")

o.append(h1("9. AFTER COLLECTION"))
for t in ["Copy the whole output folder to your workstation (scp -r, or unmount the USB media safely).",
          "Verify the archive hash against the .sha256 file and the value shown on screen; record it in your custody form.",
          "Store the archive in a restricted location (it contains secrets). The password (hostname) is weak by design - it only prevents accidental opening and automatic scanning.",
          "If the output was written to the examined server, delete it only after the copy is verified, and record the deletion.",
          "Analysis tips: manifest.csv links every file to its source; timeline/bodyfile.txt works with mactime/plaso; the RAM image (LiME format) works with Volatility 3; fs-metadata/*.e2i with debugfs and The Sleuth Kit."]:
    o.append(wrap(t, 4, "  - "))

o.append(h1("10. TROUBLESHOOTING"))
for a, b in [("'no kit BusyBox can run'", "Media mounted noexec (USB, /tmp, /dev/shm) or unsupported CPU. Remount with exec or copy the kit to an exec-allowed folder."),
             ("Many tools BLOCKED_BY_POLICY", "fapolicyd, SELinux or an EDR blocks unknown binaries. The server's programs are used where they exist (QUESTIONABLE). Ask the admin/EDR team for a temporary exception (record it)."),
             ("RAM image refused", "Kernel lockdown, /dev/crash missing or Yama ptrace_scope=3. See 03_memory/memory-access-policy.txt. Per-process dumps may still work."),
             ("KERNEL_TOO_OLD", "Go-based clients (docker, kubectl, crictl, ctr, runc) need Linux 3.2+. The rest of the kit works on older kernels; the server's clients are used."),
             ("Docker data empty", "Kit docker client too new for an old daemon: C0F retries with a lower API version, then uses the server's docker, and always copies /var/lib/docker/containers raw."),
             ("NO_SPACE", "The run stops cleanly when free space is below 10% / 2 GB (examined disk) or 512 MB (external media). Collected data is archived. Use --out on a larger disk or --no-ram/--no-timeline/--no-container-export."),
             ("Archive will not open on Windows", "Use 7-Zip. The password is the short hostname shown at the end of the run."),
             ("armv7 (32-bit ARM)", "No AVML (RAM image) and no crictl releases exist for 32-bit ARM; ctr and per-process dumps are used instead. ARMv6 (Raspberry Pi 1/Zero) is not supported."),
             ("Session dropped", "C0F keeps running. Check <work folder>/tmp/collector.log; the archive appears in the output folder when finished.")]:
    o.append(wrap(f"{a}: {b}", 6, "  - "))

o.append(h1("11. STANDARDS AND REFERENCES"))
for t in ["RFC 3227 - Guidelines for Evidence Collection and Archiving (IETF, 2002). https://www.rfc-editor.org/rfc/rfc3227",
          "ISO/IEC 27037:2012 - Guidelines for identification, collection, acquisition and preservation of digital evidence. https://www.iso.org/standard/44381.html",
          "ISO/IEC 27041:2015 - Guidance on assuring suitability and adequacy of incident investigative method. https://www.iso.org/standard/44405.html",
          "ISO/IEC 27042:2015 - Guidelines for the analysis and interpretation of digital evidence. https://www.iso.org/standard/44406.html",
          "ISO/IEC 27043:2015 - Incident investigation principles and processes. https://www.iso.org/standard/44407.html",
          "NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response. https://csrc.nist.gov/pubs/sp/800/86/final",
          "NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management (2025). https://csrc.nist.gov/pubs/sp/800/61/r3/final",
          "ACPO Good Practice Guide for Digital Evidence (UK, version 5): four principles - do not change data, competence, audit trail, responsibility.",
          "SWGDE (Scientific Working Group on Digital Evidence) best practices for live acquisition and documentation. https://www.swgde.org",
          "SANS FOR577 Linux Incident Response and Threat Hunting / FOR508 (course material and Linux cheat sheets). https://www.sans.org",
          "UAC - Unix-like Artifacts Collector 3.4.0 (artefact list used as a coverage checklist; C0F does not run it). https://github.com/tclahr/uac",
          "Volatility 3 (RAM analysis), The Sleuth Kit (bodyfile/mactime), plaso (timelines) - tools for analysing C0F output."]:
    o.append(wrap(t, 4, "  - "))

o.append(h1("12. SOURCES AND LICENSES"))
o.append(wrap("Built-from-source programs were compiled in an offline build container as fully static musl binaries (zig cc 0.17.1) from the official source archives listed below, after verifying their signatures/hashes. Vendor binaries are the official static releases, unchanged. Exact hashes of every source archive and every binary: BUILDINFO.txt. License texts: LICENSES/.", 2, "  "))
o.append(wrap("C0F itself (c0f, c0f.sh, lib/, catalog.tsv, os-profile.tsv, this README, BUILDINFO.txt and the c0f-* helpers) is dual-licensed: MIT OR GPL-2.0-or-later, at your choice (LICENSES/C0F.txt). The third-party programs keep their own licenses listed below; when you pass the kit on, keep LICENSES/ with it and be ready to provide the source archives of the GPL programs (their exact names and hashes are in BUILDINFO.txt).", 2, "  "))
o.append("")
for n, v, f, lic, src, ver in COMP:
    o.append(wrap(f"{n} {v} - {f}. License: {lic}. Source: {src}. Verified by: {ver}.", 6, "  - "))
o.append("")
o.append(wrap("Changes made for C0F: chkrootkit's chkwtmp, chklastlog and chkutmp are compiled against a header with the real glibc login-record layout (musl's own layout differs, which made the stock build misread wtmp); chkwtmp's long/time_t cast is fixed for 32-bit ARM. util-linux last/utmpdump, coreutils who and procps w are NOT shipped because musl's utmp functions are stubs (they returned empty or wrong data in tests); login records are read with c0f-logins instead, and the server's own last/who/w are run as a cross-check.", 2, "  "))

o.append(h1("13. VERSION HISTORY"))
o.append(f"  {V}  first release: 23 domains, {len(rows)} catalog items, 3 architectures, signed kit. Build details: BUILDINFO.txt")
o.append("")
open(f"{K}/README.txt", "w", encoding="utf-8").write("\n".join(o) + "\n")
print(f"README.txt: {sum(1 for _ in open(f'{K}/README.txt'))} lines")
