# C0F demo run

A complete interactive run of C0F 1.0.0 on a small test server (`demo-server`, Debian 13 container),
recorded from a real terminal. Options: `--out /evidence --no-ram --pcap-seconds 5`; total time about 2 minutes.

* Animated: [demo.svg](demo.svg)
* Interactive (type commands, answer the prompts, try wrong options and Ctrl+C): download [demo.html](demo.html)
  and open it in a browser. Every line it prints is real recorded C0F output.
* Step-by-step explanation of each screen: [GUIDE.md](GUIDE.md)

```

    mmm     mmmm    mmmmmm
  m"   "   m"  "m   #
  #        #  m #   #mmmmm
  #        #    #   #
   "mmm"    #mm#    #

  Corpus-0mnia Forensics
  Linux live-response evidence collector
  C0F 1.0.0  |  kit: /kit  |  arch: x86_64  |  user: root (invoked by root)

[C0F] Verifying kit integrity (signature + SHA-256 of every file for x86_64) ...
[C0F] KIT INTEGRITY: VERIFIED
       signature        : OK
       public key       : RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p   (compare with the key in your SOP)
       release key      : official C0F release key
       SHA256SUMS sha256: bbcbf74c2abfb8246bf3fa15541ce3640848e6f9ae935c64582ae92a3ed35d82
[C0F] Host demo-server (172.16.0.5), Debian GNU/Linux 13 (trixie), kernel 6.12.116+deb13-amd64, profile debian13+
Save output to [/evidence]:
[C0F] Self-test of kit tools on this host ...
Case / ticket number: IR-2026-0042
Examiner name: J. Analyst
Current time from a TRUSTED clock (phone/GPS), UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip: 2026-11-18 11:09:54
Examiner note (free text, Enter to skip): web shell alert from WAF on demo-server
[C0F] Estimating size (rough) ...

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
    Estimated size: ~4.6 GB (rough; ~2x needed while archiving)   Free space: 36.4 GB   Items: 227
 6. Do not power off, reboot or clean up this host before the collection has finished.
 !  Writing to the examined system overwrites free space (less chance to recover deleted files).
Type YES to continue, anything else to abort: YES
[C0F] Collection started 2026-11-18T11:09:58.044743187Z (227 catalog items). Progress is also written to /evidence/.work-demo-server_172.16.0.5_18-Nov-2026_11-09-47-55128_UTC+0000/tmp/collector.log
[C0F] (1/227) D02 02_time
[C0F] (12/227) D01 01_system
[C0F] (27/227) D03 03_memory
[C0F] (29/227) D04 04_processes
[C0F] (44/227) D03 03_memory
[C0F] (46/227) D05 05_network
[C0F] (66/227) D07 07_accounts_auth
[C0F] (68/227) D12 12_logs
[C0F] (78/227) D07 07_accounts_auth
[C0F] (95/227) D08 08_persistence
[C0F] (113/227) D09 09_services
[C0F] (120/227) D10 10_software
[C0F] (130/227) D06 06_firewall_hardening
[C0F] (148/227) D11 11_filesystem_storage
[C0F] (163/227) D13 13_web_servers
[C0F] (169/227) D14 14_databases
[C0F] (175/227) D15 15_mail
[C0F] (179/227) D16 16_applications
[C0F] (184/227) D17 17_desktop_gui
[C0F] (191/227) D18 18_containers
[C0F] (199/227) D19 19_kubernetes
[C0F] (204/227) D20 20_virtualization
[C0F] (206/227) D21 21_cloud_agents
[C0F] (208/227) D22 22_security_tools
[C0F] (210/227) D23 23_kernel_rootkit
[C0F] (220/227) D05 05_network
[C0F] (221/227) D03 03_memory
[C0F] (224/227) D10 10_software
[C0F] (225/227) D18 18_containers
[C0F] (226/227) D11 11_filesystem_storage
[C0F] Collection finished. Writing manifest, report and chain of custody ...
Current time from a TRUSTED clock again (UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip): 2026-11-18 11:11:56
Examiner closing note (Enter to skip): collection done, archive handed to SOC
[C0F] Creating encrypted archive (7-Zip AES-256, file names encrypted) ...

[C0F] KIT INTEGRITY: VERIFIED
[C0F] COLLECTION FINISHED - status: COMPLETE
 Evidence archive : /evidence/demo-server_172.16.0.5_18-Nov-2026_11-09-47-55128_UTC+0000.7z   size: 1.1 MB
 SHA-256          : 7c886ab1f44b7ea49cffca2be4e9cd092a1d383096321b84facc5ed5bd71de43
 Report (readable): /evidence/demo-server_172.16.0.5_18-Nov-2026_11-09-47-55128_UTC+0000.report.txt
 Custody summary  : /evidence/demo-server_172.16.0.5_18-Nov-2026_11-09-47-55128_UTC+0000.custody.txt
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
==============================================================================
[ CORPU5 0MNIA FORENSICS ] // Result : Execution & Acquisition Finished
------------------------------------------------------------------------------
* Decoding the shadows, sharing the light.
* Learn from experience, share the knowledge, help the community.
  Document and share the tool, just to protect the evidence.
* Sharing Knowledge, Securing Truth. Contribute & Share Responsibly.
==============================================================================
[exit code: 0]
```
