# C0F user guide - step by step

This guide shows what you type, what C0F prints, what can go wrong and how long a run takes.
The screens below are real output of C0F 1.0.0 runs on a test server named `demo-server`
(case `IR-2026-0042`, examiner `J. Analyst`); only long hashes and folder names are shortened (`…`).
The time-limit question in section 3 is shown with example values.

* Full list of what is collected (every item, command, kit tool, output file, time limit): [REFERENCE.md](REFERENCE.md)
* How to check that your kit is genuine: [VERIFY.md](VERIFY.md)
* Complete manual (purpose and forensic value of every item): `README.txt` in the kit folder

---

## 1. Before you start (checklist)

| | Check | Why |
|---|---|---|
| 1 | Written approval from the system owner / incident lead | C0F reads credential files, memory and personal data |
| 2 | Kit verified **on your workstation** with the official key ([VERIFY.md](VERIFY.md)) | a modified kit could hide evidence |
| 3 | Output target chosen: USB disk or network share (preferred), or the server's own disk | writing to the examined disk overwrites free space |
| 4 | Free space: about **RAM size + 5 to 30 GB**, and twice that while archiving (the warning screen shows an estimate) | see [section 9](#9-disk-space) |
| 5 | SOC / EDR team informed | memory dump and packet capture can trigger EDR alerts |
| 6 | A trusted clock at hand (phone, GPS) | C0F records it next to the server clock to measure clock drift |
| 7 | Root access (`sudo` or root login) | without root most items return DENIED |
| 8 | Do **not** reboot, power off or clean up the server before and during collection | volatile evidence is lost |

---

## 2. Step by step (interactive run)

### Step 1 - copy the kit to the server and start it

Copy the whole `C0F-KIT/` folder (USB disk, network share, or `scp`) and start it as root:

```
$ cd /media/usb/C0F-KIT
$ sudo ./c0f
```

No `/bin/sh` on the server (minimal or damaged system)? Start the collector with the kit's own shell:

```
# ./bin/x86_64/busybox sh ./c0f.sh          (aarch64 / armv7: use bin/aarch64 or bin/armv7)
```

### Step 2 - kit integrity check (automatic)

C0F checks its own signature and the SHA-256 of every file it will use **before** anything else:

```
[C0F] Verifying kit integrity (signature + SHA-256 of every file for x86_64) ...
[C0F] KIT INTEGRITY: VERIFIED
       signature        : OK
       public key       : RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p   (compare with the key in your SOP)
       release key      : official C0F release key
       SHA256SUMS sha256: 635d360c…f463333
[C0F] Host demo-server (172.16.0.5), Debian GNU/Linux 13 (trixie), kernel 6.12.116+deb13-amd64, profile debian13+
```

What to check: `KIT INTEGRITY: VERIFIED` and `release key : official C0F release key`.
If you see `NOT the official C0F release key`, the kit was built or signed by someone else: stop and use
a kit you verified yourself. Other results (QUESTIONABLE, COMPROMISED) are explained in [section 6](#6-errors-and-warnings).

### Step 3 - answer the questions

| Prompt | What to type | Example |
|---|---|---|
| `Save output to [/media/usb/C0F-KIT/demo-server]:` | Enter = accept the folder in brackets, or type another folder | *(Enter)* |
| `Case / ticket number:` | your case or ticket ID (not asked when `--case` is given) | `IR-2026-0042` |
| `Examiner name:` | your name (not asked when `--examiner` is given) | `J. Analyst` |
| `Current time from a TRUSTED clock (phone/GPS), UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip:` | the UTC time from your phone/GPS | `2026-11-18 10:16:49` |
| `Examiner note (free text, Enter to skip):` | why you collect, ticket context | `web shell alert from WAF on demo-server` |

Between the questions C0F tests every kit tool on this server (`Self-test of kit tools`) and estimates the size.

### Step 4 - read the warning screen and type YES

```
[C0F] WARNING - READ BEFORE CONTINUING
 1. Authorized use only. Run this tool only with approval from the system owner / incident lead.
 2. Live-response evidence collection on host demo-server (172.16.0.5), Debian GNU/Linux 13 (trixie),
    as user root (invoked by root). Kit integrity: VERIFIED.
 3. It reads system files, logs, memory, processes, network state, containers and credential files
    (/etc/shadow, keys, tokens, process environments). The result is HIGHLY SENSITIVE.
 4. It does not change configuration or restart services, but it WILL: create files in the output folder,
    add entries to system logs (sudo/audit/journal), use CPU, disk I/O and disk space, and may trigger
    EDR alerts (memory dump, packet capture). Inform the SOC/EDR team first.
 5. Output folder : /evidence   (on the examined system's disk: YES)
    Estimated size: ~4.5 GB (rough; ~2x needed while archiving)   Free space: 37.7 GB   Items: 227
 6. Do not power off, reboot or clean up this host before the collection has finished.
 !  Writing to the examined system overwrites free space (less chance to recover deleted files).
Type YES to continue, anything else to abort: YES
```

Only the exact word `YES` (capital letters) starts the collection. Anything else ends the run:

```
Type YES to continue, anything else to abort: no
[C0F] Aborted by operator before collection.
```
(exit code 2, nothing collected, the output folder is left empty)

### Step 5 - collection (no input needed)

```
[C0F] Collection started 2026-11-18T10:16:52.736185584Z (227 catalog items). Progress is also written to /evidence/.work-…/tmp/collector.log
[C0F] (1/227) D02 02_time
[C0F] (12/227) D01 01_system
[C0F] (27/227) D03 03_memory
[C0F] (29/227) D04 04_processes
 ...
[C0F] (226/227) D11 11_filesystem_storage
[C0F] Collection finished. Writing manifest, report and chain of custody ...
```

One line is printed each time a new domain starts. Items that fail are reported as `[C0F] WARN ...` and the
run continues. If the SSH session drops, the collection keeps running (follow `collector.log`).
If an item reaches its time limit you are asked what to do - see [section 3](#3-when-an-item-reaches-its-time-limit).

### Step 6 - closing questions

```
Current time from a TRUSTED clock again (UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip): 2026-11-18 10:18:35
Examiner closing note (Enter to skip): collection done, archive handed to SOC
[C0F] Creating encrypted archive (7-Zip AES-256, file names encrypted) ...
```

### Step 7 - result

```
[C0F] KIT INTEGRITY: VERIFIED
[C0F] COLLECTION FINISHED - status: COMPLETE
 Evidence archive : /evidence/demo-server_172.16.0.5_18-Nov-2026_10-16-41-34528_UTC+0000.7z   size: 1.1 MB
 SHA-256          : 2f71746d…b60f3de2f
 Report (readable): /evidence/demo-server_172.16.0.5_18-Nov-2026_10-16-41-34528_UTC+0000.report.txt
 Custody summary  : /evidence/demo-server_172.16.0.5_18-Nov-2026_10-16-41-34528_UTC+0000.custody.txt
 Archive password : the short hostname of this server: demo-server
 Collected: 119   Empty: 27   Not found / not applicable: 81   Not run (no space / interrupted): 0   Failed/timeout/denied: 0   Warnings: 0
 working folder removed after a successful archive test

 NEXT STEPS
 1. Download the whole folder /evidence/ , for example from your workstation:
      scp -r <user>@172.16.0.5:"/evidence" .
 2. Verify the archive hash after download (sha256sum, or on Windows: certutil -hashfile <file> SHA256).
 3. Record the hash and the transfer in the chain-of-custody form.
 4. The archive contains password hashes, keys, tokens and personal data. Store it in a restricted location.
 5. If the output is on the examined system, remove it only after the copy is verified (note the deletion in the form).
```

(The demo server was a small container: 1.1 MB, 2 minutes. A real server gives gigabytes - see [section 8](#8-how-long-does-it-take).)

| Status | Meaning | Exit code |
|---|---|---|
| `COMPLETE` | every item ran (OK, EMPTY, NOT FOUND or NOT APPLICABLE are all normal results) | 0 |
| `PARTIAL (...)` | some items failed, timed out, were denied or skipped for disk space, or the archive was not created; the reason is in brackets and in `report.txt` | 1 |
| `INTERRUPTED` | stopped with Ctrl+C; what was collected until then is archived | 2 |

### Step 8 - open the result on your workstation

```
$ sha256sum -c demo-server_…_UTC+0000.sha256          # Windows: certutil -hashfile <file>.7z SHA256
$ 7z x demo-server_…_UTC+0000.7z                       # password: demo-server
```

Use 7-Zip on Windows (Windows Explorer cannot open AES-encrypted 7z files) or `7z`/`7zz` on Linux/macOS.
Start with `99_custody/report.txt` (summary, COLLECTED / NOT COLLECTED / FAILED lists), then the domain folders
`01_system` ... `23_kernel_rootkit`. `99_custody/manifest.csv` has the SHA-256, MD5 and original timestamps of every file.

---

## 3. When an item reaches its time limit

Every item has its own time limit (shown in [REFERENCE.md](REFERENCE.md), column **Limit**):

| Limit | Items | Typical items |
|---|---|---|
| 10 s - 2 min | 129 | system info, network state, accounts, configuration |
| 5 - 20 min | 53 | logs, package checks, container inspection |
| 30 - 60 min | 31 | package verification, large log trees, Kubernetes |
| 2 - 8 h | 14 | RAM image, filesystem timeline, e2image, container export |

In an **interactive** run C0F asks before it stops an item. The item keeps running while the question is shown
(example values):

```
[C0F] D10-009 is still running after 30m00s (its time limit). Output so far: 0.8 MB.
      Press Enter to stop it now (partial output is kept), or type minutes to wait longer (1-1440).
      No answer within 2 minutes = stop.
      Wait how many more minutes? 15
[C0F] D10-009: waiting 15 more minutes (limit now 45m00s)
```

| You type | Result |
|---|---|
| a number 1-1440 | the limit is extended by that many minutes; you are asked again when the new limit is reached. The report notes `time limit extended by operator: +15 min` |
| Enter | the item is stopped now; status `TIMEOUT`, the partial output is kept |
| nothing for 2 minutes | same as Enter |
| text or an invalid number | `[C0F] 'abc' is not a number of minutes (1-1440). Press Enter to stop, or type e.g. 15` and the question is repeated |

Options:

* `--timeout-factor N` multiplies every limit by N (1-100), for very large or slow servers. Example: `--timeout-factor 3`.
* `--no-timeout-prompt` never asks: an item that reaches its limit is stopped and the partial output kept.
* With `--yes` (unattended) C0F never asks; it behaves like `--no-timeout-prompt`.

---

## 4. Unattended run (no questions)

```
$ sudo ./c0f --yes --case IR-2026-0042 --examiner "J. Analyst" --out /mnt/evidence
```

`--yes` needs `--case` and `--examiner`. The warning screen is still printed (and written to the log), followed by
`[C0F] --yes given: continuing.` Useful for remote execution (SSH, EDR live-response shell) and scheduled runs.
Without a terminal and without `--yes` C0F cannot ask for YES and stops (see the table below).

---

## 5. Common options

| Option | Effect |
|---|---|
| `--out DIR` | output folder (default: `<kit folder>/<HOSTNAME>`) |
| `--case ID`, `--examiner NAME` | answers for the first two questions |
| `--yes` | no questions (needs `--case` and `--examiner`) |
| `--password TEXT` / `--password-prompt` | own archive password instead of the short hostname |
| `--no-ram` | no RAM image (saves RAM-size disk space and time) |
| `--no-swap`, `--no-pcap`, `--no-timeline`, `--no-e2image`, `--no-container-export`, `--no-process-dumps`, `--no-db-binlogs`, `--no-db-wal`, `--no-db-data`, `--no-screenshot`, `--no-clipboard` | turn off one large or intrusive part (all are ON by default) |
| `--pcap-seconds N` | packet capture length (default 60) |
| `--since DAYS` | "recently changed" window for summaries (default 30) |
| `--timeout-factor N`, `--no-timeout-prompt` | see [section 3](#3-when-an-item-reaches-its-time-limit) |
| `--dry-run` | show what would be collected, collect nothing |
| `--self-test` | verify the kit and test every kit tool on this server, then exit |
| `--keep-work` | keep the unencrypted working folder after the archive is tested |
| `--help`, `--version` | |

A light first pass when disk space or time is short:

```
$ sudo ./c0f --no-ram --no-swap --no-process-dumps --no-container-export --no-e2image --no-timeline
```

---

## 6. Errors and warnings

Messages in the tables are copied from real runs of C0F 1.0.0. The "During collection" messages show the format; the item IDs there are examples.

### Wrong command or option (nothing is collected)

| You run | C0F prints | Fix | Exit |
|---|---|---|---|
| `./c0f --fast` | `[C0F] unknown option: --fast (see --help)` | check the option name with `./c0f --help` | 2 |
| `./c0f --pcap-seconds abc` | `[C0F] --pcap-seconds needs a number` | give seconds, e.g. `--pcap-seconds 30` | 2 |
| `./c0f --since 30days` | `[C0F] --since needs a number of days` | e.g. `--since 30` | 2 |
| `./c0f --timeout-factor 0` | `[C0F] --timeout-factor needs a whole number from 1 to 100` | e.g. `--timeout-factor 3` | 2 |
| `./c0f --yes --out /evidence` | `[C0F] ERROR --yes needs --case and --examiner` | add `--case ID --examiner NAME` | 2 |
| `./c0f` as a normal user, no sudo on the server | `[C0F] ERROR C0F must run as root (uid 0). No sudo found. Log in as root and run: /kit/c0f` | log in as root | 2 |
| `./c0f` as a normal user with sudo | `[C0F] Not running as root: re-starting with sudo (/usr/bin/sudo).` then the sudo password prompt | type your sudo password | - |
| no terminal (e.g. a remote command) and no `--yes` | `[C0F] No terminal to answer the question. For an unattended run use: --yes --case ID --examiner NAME` then `[C0F] Aborted by operator before collection.` | use `--yes --case --examiner` | 2 |
| `YES` not typed at the warning screen | `[C0F] Aborted by operator before collection.` | run again and type `YES` | 2 |

### Output folder problems (nothing is collected)

| Situation | C0F prints | Fix | Exit |
|---|---|---|---|
| read-only media or folder | `[C0F] ERROR cannot create output folder /mnt/ev (read-only media?). Use --out DIR` | `--out` to a writable disk or share | 2 |
| folder exists but is not writable | `[C0F] ERROR output folder DIR is not writable. Use --out DIR` | same | 2 |
| folder in RAM (tmpfs: `/tmp` on many systems, `/dev/shm`, `/run`) | `[C0F] ERROR output folder /ram/ev is in RAM (tmpfs): it would consume the server's memory. Use --out DIR on a disk or USB` | `--out` on a disk or USB | 2 |
| another C0F run uses the same folder | `[C0F] ERROR another C0F run (pid 1) is using /evidence` | wait for it, or use another `--out` | 2 |

### Kit problems

| Situation | C0F prints | Meaning / fix | Exit |
|---|---|---|---|
| a non-core kit program was changed or is missing | `[C0F] KIT INTEGRITY: QUESTIONABLE` + `bin/x86_64/lsns  MODIFIED  NOT_USED` + `[C0F] WARN 1 kit tool(s) not usable on this host: lsns (server programs will be used where they exist)` | the run continues without that program; affected results are marked in the report. Replace the kit with a verified copy for court-grade work | 0/1 |
| a core file (`c0f.sh`, `lib/`, `busybox`, `minisign`, `sha256sum`, ...) was changed, or the signature is wrong | `[C0F] KIT INTEGRITY: COMPROMISED` + `c0f.sh  MODIFIED  STOP` + `[C0F] KIT VERIFICATION FAILED - collection NOT started` + `core problem: c0f.sh(MODIFIED)` + `[C0F] Details written to /evidence/C0F-KIT-VERIFY-FAILED_<time>.txt` | use a clean, verified kit. The details file lists every file with expected and found SHA-256 | 3 |
| same, with `--force-untrusted-kit test` | `[C0F] --force-untrusted-kit ignored: the reason 'test' is too short (4 characters, at least 10 needed)` and the stop above | the reason must have at least 10 characters | 3 |
| same, with `--force-untrusted-kit "lab test of a modified kit"` | `[C0F] WARN kit core verification failed (c0f.sh(MODIFIED)) - continuing because of --force-untrusted-kit: lab test of a modified kit` | runs with status COMPROMISED recorded everywhere; only for lab work | 0/1 |
| signed with another key | `release key : NOT the official C0F release key - this is not an official C0F release (private build or replaced kit)` | the kit is consistent, but not an official release: verify where it came from | - |
| kit on a `noexec` mount, or unsupported CPU | `[C0F] ERROR: no kit BusyBox can run on this machine (supported: x86_64, aarch64, armv7).` | remount with exec, or copy the kit to an exec-allowed folder | 3 |

### During collection (the run continues)

| Message | Meaning |
|---|---|
| `[C0F] WARN D05-013 FAILED (EXIT_NONZERO): ...` | one item failed; reason and first error line follow. Listed in `failures.csv` |
| `[C0F] WARN D10-009 TIMEOUT (TIMEOUT): ...` | the item reached its time limit and was stopped; partial output kept |
| `... FAILED (SERVER_TOOL_CRASHED)` | a program of the examined server crashed (SIGSEGV, SIGILL, ...): suspect tampering, damaged files or an incompatible kernel |
| `[C0F] WARN D01-003 EXPECTED_BUT_MISSING: ...` | a command that this OS version normally has is missing: possible tampering or a stripped image |
| `[C0F] WARN free space below the reserve (… MB): large items (RAM, swap, process dumps, pcap, timeline, e2image, container export, DB files) are skipped from now on; all other items continue` | disk is getting full: see [section 9](#9-disk-space) |
| `[C0F] WARN free space below the hard floor (… MB): collection stops cleanly (NO_SPACE)` | nothing more is written; what was collected is archived. Status `PARTIAL (stopped: NO_SPACE)` |
| `[C0F] WARN working folder (… MB) is larger than the free space (… MB): ...` | the archive may not fit; 7-Zip is stopped before the disk is full and the working folder is kept |

### Stopping a run (Ctrl+C)

Press Ctrl+C once during collection:

```
^C[C0F] WARN interrupted by operator: the remaining 107 items are skipped, the collected data is archived (Ctrl+C again during archiving stops the archive)
[C0F] Collection finished. Writing manifest, report and chain of custody ...
 ...
[C0F] COLLECTION FINISHED - status: INTERRUPTED
 Evidence archive : /evidence/demo-server_…_UTC+0000.7z   size: 0.1 MB
 Collected: 71   Empty: 12   Not found / not applicable: 36   Not run (no space / interrupted): 108   Failed/timeout/denied: 0   Warnings: 1
```

The running item is stopped (partial output kept), the rest is recorded as `SKIPPED INTERRUPTED`, and the
collected data is hashed and archived as usual (exit code 2). A second Ctrl+C while the archive is being created
stops 7-Zip: the partial archive is removed and the working folder is kept **unencrypted**:

```
[C0F] WARN archive STOPPED by the operator. Partial archive removed; working folder kept (NOT encrypted): /evidence/.work-…
 Evidence archive : NOT CREATED (stopped by operator)
 Evidence folder  : /evidence/.work-…   (NOT encrypted: copy it to external media and archive it there)
```

---

## 7. Exit codes

| Code | Meaning |
|---|---|
| 0 | COMPLETE |
| 1 | PARTIAL (failures, timeouts, denied items, items skipped for disk space, or archive not created) |
| 2 | usage error, aborted before collection, or INTERRUPTED (Ctrl+C) |
| 3 | kit problem (verification failed, no usable BusyBox) |

---

## 8. How long does it take

Measured runs of C0F 1.0.0:

| Server | Options | Collection | Hash + archive + test | Total | Archive |
|---|---|---|---|---|---|
| minimal container (Debian 13) | `--no-ram --pcap-seconds 5` | 1.5 min | < 0.5 min | **2 min** | 1.1 MB |
| VPS, 4 vCPU, 15 GB RAM, SSD, 2.6 million files, 14 running containers, X11 desktop | defaults except `--no-container-export` (RAM 16 GB, swap, process dumps, timeline, pcap, e2image) | ~40 min ¹ | ~65 min (31.5 GB) | **~1 h 45 min** | 3.9 GB |
| same VPS | light: `--no-ram --no-swap --no-process-dumps --no-container-export --no-e2image --no-timeline` | 41 min | 11 min (7.3 GB) | **~52 min** | 1.1 GB |

¹ measured 72 min with a pre-release build in which two items were slow (package-ownership check stopped at its 30 min limit, clock-change search 9 min); both were fixed before 1.0.0, where they take about 4 min and 1.5 min.
On this server most of the collection time goes to package verification, log and filesystem scans, not to the large optional items.

Measured speeds on that VPS (use them to estimate your own server):

| Step | Speed | Grows with |
|---|---|---|
| RAM image (AVML) | 16 GB in 62 s (~250 MB/s to SSD) | RAM size and write speed of the output (USB 3 disk ~80-150 MB/s, 1 Gbit share ~100 MB/s) |
| SHA-256 + MD5 manifest | ~95 MB/s (31.5 GB in 5.5 min) | collected data size |
| 7-Zip archive + test (runs with low CPU priority) | ~2 min per GB on 4 vCPU | collected data size, number of CPU cores, server load |
| other items | ~40 min on that server | number of files (timeline), logs, packages, containers |

Rough estimates (full run with RAM image; output to a local SSD; "light" = the light options above):

| Server size | Typical content | Full run | Light run |
|---|---|---|---|
| Small: 1-2 vCPU, 2-4 GB RAM | < 1 million files, no containers | 20-45 min | 15-30 min |
| Medium: 4 vCPU, 8-16 GB RAM | 1-3 million files, some containers | 1-2 h | 40-60 min |
| Large: 8-16 vCPU, 32-64 GB RAM | 3-10 million files, many containers | 2.5-5 h | 1-2.5 h |
| Very large: 32+ vCPU, 128 GB+ RAM, big databases | > 10 million files | 5 h or more: plan with `--timeout-factor 3`, output to a fast external disk, or a light run first | 2 h or more |

The archive step dominates on big servers: roughly 4 min/GB with 2 vCPU, 2 min/GB with 4, 1 min/GB with 8 and
0.6 min/GB with 16 vCPU (collected data before compression; a RAM image counts with its full size).
A busy server is slower because C0F runs 7-Zip with low priority.

---

## 9. Disk space

* The warning screen shows `Estimated size` and `Free space`. Plan for about **twice** the estimate: the
  working folder and the archive exist at the same time until the archive is tested.
* RAM image = RAM size; swap copy = swap size; process dumps and container export can be several GB.
* C0F protects the disk it writes to:
  * **reserve** - 10 % of the disk, at least 2 GB (512 MB on external media): below it the large items
    (RAM, swap, process dumps, pcap, timeline, e2image, container export, DB files) are skipped; everything else
    is still collected. Status `PARTIAL (low disk space: N large items not run)`.
  * **hard floor** - 5 %, at least 1 GB (256 MB on external media): below it nothing more is written; the
    collection stops cleanly and 7-Zip is stopped before the disk is full.

---

## 10. What you get

```
<output folder>/
  <HOST>_<IP>_<DD-Mmm-YYYY>_<HH-MM-SS-sssss>_UTC<+hhmm>.7z    encrypted archive (AES-256, file names encrypted)
  <same name>.sha256         SHA-256 and MD5 of the archive
  <same name>.report.txt     readable report (also inside the archive)
  <same name>.custody.txt    chain-of-custody summary with a handover form (also inside the archive)
```

Inside the archive: `01_system` ... `23_kernel_rootkit` (one folder per domain, empty when nothing was found)
and `99_custody/` (`manifest.csv`, `report.txt`, `chain-of-custody.txt`, `failures.csv`, `not-collected.csv`,
`items.tsv`, `tools-used.csv`, `kit-integrity.csv`, `kit-selftest.csv`, `collector.log`).
Every status and reason code is explained in section 8 of `README.txt`.
