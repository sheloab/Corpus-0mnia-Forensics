# C0F 1.0.0 - collection reference

Generated from `catalog.tsv` and the collection functions of this kit, so it always matches the kit. Every item runs as its own process with a time limit; a failing item is reported and the run continues.

**How** shows the command (CMD), the files/folders copied with `c0f-copy` (COPY), or the collection function (FUNC, in `lib/c0f-lib.sh`). **Kit tools** are the trusted static programs from `bin/<arch>/` that the item uses (shell built-ins and BusyBox/coreutils basics such as `cat`, `find`, `sort` are not listed). **Server programs** are used only when they exist on the examined system (e.g. `rpm`, `systemctl`); each use is recorded as `UNTRUSTED_TOOL` in `tools-used.csv`. **Limit** is the default time limit (`--timeout-factor N` multiplies it; in an interactive run you are asked whether to wait longer).

Status of every item after a run: `99_custody/items.tsv`, `report.txt`, `failures.csv`, `not-collected.csv`.

## Domains

| Domain | Output folder | Items |
|---|---|---|
| [D01 System identity and state](#d01-system-identity-and-state) | `01_system/` | 15 |
| [D02 Time and time zone](#d02-time-and-time-zone) | `02_time/` | 11 |
| [D03 Memory](#d03-memory) | `03_memory/` | 7 |
| [D04 Processes](#d04-processes) | `04_processes/` | 15 |
| [D05 Network](#d05-network) | `05_network/` | 21 |
| [D06 Firewall and hardening](#d06-firewall-and-hardening) | `06_firewall_hardening/` | 18 |
| [D07 Accounts and authentication](#d07-accounts-and-authentication) | `07_accounts_auth/` | 19 |
| [D08 Persistence](#d08-persistence) | `08_persistence/` | 18 |
| [D09 Services](#d09-services) | `09_services/` | 7 |
| [D10 Software and packages](#d10-software-and-packages) | `10_software/` | 11 |
| [D11 Filesystem and storage](#d11-filesystem-and-storage) | `11_filesystem_storage/` | 17 |
| [D12 Logs](#d12-logs) | `12_logs/` | 10 |
| [D13 Web servers](#d13-web-servers) | `13_web_servers/` | 6 |
| [D14 Databases](#d14-databases) | `14_databases/` | 6 |
| [D15 Mail](#d15-mail) | `15_mail/` | 4 |
| [D16 User applications](#d16-user-applications) | `16_applications/` | 5 |
| [D17 Desktop / GUI](#d17-desktop--gui) | `17_desktop_gui/` | 7 |
| [D18 Containers](#d18-containers) | `18_containers/` | 9 |
| [D19 Kubernetes](#d19-kubernetes) | `19_kubernetes/` | 5 |
| [D20 Virtualization](#d20-virtualization) | `20_virtualization/` | 2 |
| [D21 Cloud agents](#d21-cloud-agents) | `21_cloud_agents/` | 2 |
| [D22 Security tools](#d22-security-tools) | `22_security_tools/` | 2 |
| [D23 Kernel and rootkit checks](#d23-kernel-and-rootkit-checks) | `23_kernel_rootkit/` | 10 |

Total: 227 items.

## D01 System identity and state

Output folder `01_system/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D01-001 | Kernel version, build, boot parameters, hostname, boot id. | CMD `uname -a; echo; for f in /proc/version /proc/cmdline /proc/sys/kernel/osrelease /proc/sys/kernel/version /proc/sys/kernel/hostname /proc/sys/kernel/domainname /proc/sys/…` | - | - | `kernel-identity.txt` | 10s |
| D01-002 | Distribution release files and machine identity files. | COPY /etc/os-release /usr/lib/os-release /etc/lsb-release /etc/debian_version /etc/redhat-release /etc/centos-release /etc/rocky-release /etc/almalinux-re… | - | - | `-` | 30s |
| D01-003 | Which OS profile C0F selected, what the profile expects on this OS and what is missing. | FUNC `os_profile_report` | - | - | `os-profile.txt` | 20s |
| D01-004 | Static/transient hostname, chassis, virtualization and OS as reported by the system tools. | CMD `srv hostnamectl 2>&1; srv lsb_release -a 2>&1` | - | hostnamectl, lsb_release | `hostnamectl.txt` | 15s |
| D01-005 | Detect virtualization, container and cloud environment without calling any network service. | FUNC `virt_detect` | - | systemd-detect-virt | `virtualization.txt` | 30s |
| D01-006 | Full DMI/SMBIOS table (system, board, BIOS, chassis, memory). | CMD `dmidecode 2>&1` | `dmidecode` | - | `hardware/dmidecode.txt` | 30s |
| D01-007 | DMI values exposed by the kernel in sysfs. | CMD `for f in /sys/class/dmi/id/*; do [ -f "$f" ] && [ -r "$f" ] && printf '%s=%s\n' "${f##*/}" "$(cat "$f" 2>/dev/null)"; done` | - | - | `hardware/dmi-sysfs.txt` | 20s |
| D01-008 | CPU model/flags, memory statistics. | CMD `cat /proc/cpuinfo; echo; cat /proc/meminfo; echo; cat /proc/iomem 2>/dev/null \| head -n 200` | - | - | `hardware/cpu-memory.txt` | 20s |
| D01-009 | Memory and swap usage, short vmstat sample. | CMD `free -w; echo; vmstat 1 3; echo; cat /proc/swaps; echo; cat /proc/pressure/memory 2>/dev/null` | `vmstat` | - | `hardware/memory-usage.txt` | 20s |
| D01-010 | PCI and USB devices currently attached. | CMD `echo '== lspci (IDs only, no name database)'; lspci -mk 2>&1; echo; echo '== lsusb'; lsusb 2>&1; echo; for d in /sys/bus/usb/devices/*; do [ -f "$d/idVendor" ] && echo "…` | - | - | `hardware/pci-usb.txt` | 30s |
| D01-011 | Block devices with model, serial, transport, filesystem and mount points. | CMD `lsblk -a -o NAME,KNAME,MAJ:MIN,TYPE,SIZE,RO,RM,HOTPLUG,TRAN,VENDOR,MODEL,SERIAL,WWN,FSTYPE,LABEL,UUID,MOUNTPOINTS 2>&1` | `lsblk` | - | `hardware/disks.txt` | 30s |
| D01-012 | Network interface MAC addresses and drivers. | CMD `for d in /sys/class/net/*; do n=${d##*/}; echo "$n mac=$(cat "$d/address" 2>/dev/null) perm=$(cat "$d/addr_assign_type" 2>/dev/null) operstate=$(cat "$d/operstate" 2>/de…` | - | - | `hardware/nic-identity.txt` | 20s |
| D01-013 | Installed kernels and initramfs files with hashes; module trees. | CMD `ls -la --time-style=full-iso /boot 2>&1; echo; sha256sum /boot/* 2>/dev/null; echo; ls -la --time-style=full-iso /lib/modules /usr/lib/modules 2>/dev/null` | - | - | `kernels-installed.txt` | 20s |
| D01-014 | Estimate when the OS was installed (root filesystem creation time, installer logs, oldest package). | FUNC `os_install_time` | `dumpe2fs` | rpm | `os-install-time.txt` | 1 min |
| D01-015 | Identity, capabilities and namespaces of the collector itself. | CMD `id; echo "SUDO_USER=${SUDO_USER:-} SUDO_UID=${SUDO_UID:-}"; cat /proc/self/status \| grep -E '^(Cap\|Uid\|Gid\|NoNewPrivs\|Seccomp)'; cat /proc/self/cgroup; readlink /proc/se…` | - | - | `collector-context.txt` | 10s |

## D02 Time and time zone

Output folder `02_time/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D02-001 | Server clock at collection start in UTC and local time, with nanoseconds. | CMD `printf 'utc=%s\nlocal=%s\nepoch_ns=%s\ntz_env=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$(date '+%Y-%m-%dT%H:%M:%S.%N %z %Z')" "$(date +%s%N)" "${TZ:-unset}"` | - | - | `clock-now.txt` | 10s |
| D02-002 | Seconds since boot and load average. | CMD `cat /proc/uptime; echo; cat /proc/loadavg; echo; uptime` | - | - | `uptime.txt` | 10s |
| D02-003 | System time zone from every place a distro may store it. | CMD `for f in /etc/timezone /etc/sysconfig/clock /etc/adjtime /etc/default/rcS; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done; echo "== /etc/localtime -> $(readlink /et…` | - | - | `timezone-files.txt` | 10s |
| D02-004 | Identify the zone of /etc/localtime when it is a copied file (compare with /usr/share/zoneinfo). | FUNC `tz_identify` | - | - | `timezone-identify.txt` | 30s |
| D02-005 | systemd view of local time, UTC, RTC, zone, NTP state. | CMD `srv timedatectl status; echo; srv timedatectl show; echo; srv timedatectl timesync-status 2>&1` | - | timedatectl | `timedatectl.txt` | 20s |
| D02-006 | Hardware clock (RTC) value read directly. | CMD `hwclock --show --verbose 2>&1; echo; for f in /sys/class/rtc/rtc0/date /sys/class/rtc/rtc0/time /sys/class/rtc/rtc0/since_epoch /sys/class/rtc/rtc0/hctosys; do [ -r "$f"…` | `hwclock` | - | `rtc.txt` | 15s |
| D02-007 | NTP synchronisation state and sources (chrony). | CMD `{ echo "== chronyc tracking"; srv chronyc -n tracking; echo "== chronyc sources"; srv chronyc -n sources -v; } 2>&1` | - | chronyc | `chrony.txt` | 20s |
| D02-008 | NTP peers and synchronisation (ntpd). | CMD `{ srv ntpq -pn; srv ntpstat; } 2>&1` | - | ntpq, ntpstat | `ntpq.txt` | 20s |
| D02-009 | NTP client configuration and drift files. | COPY /etc/chrony.conf /etc/chrony /etc/ntp.conf /etc/ntpsec /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d /var/lib/chrony/drift /var/lib/ntp/n… | - | - | `-` | 30s |
| D02-010 | Search logs and shell histories for clock/zone changes (date -s, timedatectl set-time, hwclock --set, 'Time has been changed'). | FUNC `time_change_evidence` | `hwclock` | been, journalctl | `time-change-evidence.txt` | 15 min |
| D02-011 | Version of the time zone database. | CMD `srv dpkg-query -W -f '${Package} ${Version}\n' tzdata 2>/dev/null \|\| srv rpm -q tzdata 2>/dev/null \|\| srv apk info -v tzdata 2>/dev/null; head -n 1 /usr/share/zoneinfo/t…` | - | apk, dpkg-query, rpm | `tzdata-version.txt` | 30s |

## D03 Memory

Output folder `03_memory/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D03-001 | Full physical memory image with AVML (Microsoft, static) in LiME format. *(off with `--no-ram`; sensitive; changes: Reads all RAM; uses CPU and disk; may trigger EDR alerts.)* | FUNC `ram_dump` | `avml` | - | `ram` | 2 h |
| D03-002 | Kernel settings that allow or forbid memory acquisition. | CMD `echo "ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null \|\| echo absent)"; echo "lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null \|\| echo absent)"…` | - | - | `memory-access-policy.txt` | 10s |
| D03-010 | Dump memory of suspicious processes (deleted executable, running from /tmp,/dev/shm,/var/tmp, memfd:, fake kernel threads, executable not found on disk). *(off with `--no-process-dumps`; sensitive; changes: Reads target process memory (no attach, no stop).)* | FUNC `proc_memdumps` | `c0f-memdump` | - | `process-dumps` | 1 h |
| D03-011 | Recover unsaved shell history from the memory of running interactive shells (bash/zsh/sh/ash). *(off with `--no-process-dumps`; sensitive)* | FUNC `shell_memory_history` | `c0f-memdump` | - | `shell-memory` | 10 min |
| D03-020 | Copy active swap devices/files (raw). *(off with `--no-swap`; sensitive)* | FUNC `swap_copy` | `blockdev`, `c0f-copy` | - | `swap` | 2 h |
| D03-021 | Crash dumps and core files kept by the system. *(sensitive)* | COPY /var/crash /var/lib/systemd/coredump /var/spool/abrt /var/lib/apport/coredump /var/tmp/abrt | - | - | `-` | 30 min |
| D03-022 | systemd-coredump index (which program crashed, when, signal). | CMD `srv coredumpctl list --no-pager 2>&1` | - | coredumpctl | `coredumpctl.txt` | 30s |

## D04 Processes

Output folder `04_processes/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D04-001 | All processes with parent, owner, start time, state and full command line. | CMD `ps -eo pid,ppid,pgid,sid,tty,user:32,uid,gid,lstart,etimes,stat,pcpu,pmem,vsz,rss,nlwp,wchan:32,comm,args --sort=pid -ww` | `ps` | - | `ps-full.txt` | 1 min |
| D04-002 | Process tree (forest view). | CMD `ps auxwwf` | `ps` | - | `ps-tree.txt` | 1 min |
| D04-003 | All threads of all processes. | CMD `ps -eLo pid,tid,user,stat,wchan:32,comm -ww` | `ps` | - | `threads.txt` | 1 min |
| D04-004 | Per-PID snapshot from /proc: cmdline, environ, status, exe link + hash, cwd, root, maps, fd list, cgroup, namespaces, limits, loginuid, sessionid, mountinfo id. *(sensitive)* | FUNC `proc_details` | - | - | `proc` | 15 min |
| D04-005 | Copy the executable of processes whose binary is deleted, in a temp folder, memfd or not owned by any package path. *(sensitive)* | FUNC `proc_exe_copies` | - | - | `exe-copies` | 30 min |
| D04-006 | Open files, sockets and pipes of every process. | CMD `lsof -n -P -b -w +c 0 2>&1` | `lsof` | - | `lsof.txt` | 5 min |
| D04-007 | Files held open that are deleted, memfd-backed or in temp folders (read directly from /proc). | CMD `for p in /proc/[0-9]*; do pid=${p##*/}; for fd in "$p"/fd/*; do l=$(readlink "$fd" 2>/dev/null) \|\| continue; case "$l" in *'(deleted)'*\|memfd:*\|/dev/shm/*\|/tmp/*\|/var/tm…` | - | - | `open-deleted-or-temp-files.txt` | 2 min |
| D04-008 | Copy the content of deleted files still held open by a process (through /proc/<pid>/fd). *(sensitive)* | FUNC `deleted_open_file_copies` | - | - | `deleted-open-files` | 30 min |
| D04-009 | All namespaces with owning process. | CMD `lsns -o NS,TYPE,PATH,NPROCS,PID,PPID,COMMAND,UID,USER 2>&1; echo; ls -l /run/netns /var/run/netns 2>/dev/null` | `lsns` | - | `namespaces.txt` | 1 min |
| D04-010 | cgroup membership of every process. | CMD `for p in /proc/[0-9]*; do printf '%s\t%s\t' "${p##*/}" "$(cat "$p/comm" 2>/dev/null)"; tr '\n' ' ' < "$p/cgroup" 2>/dev/null; echo; done` | - | - | `cgroups-per-process.tsv` | 1 min |
| D04-011 | Find processes named like kernel threads ([kworker], [kthreadd]) that have an executable or memory map. | FUNC `kthread_check` | - | exe | `fake-kernel-threads.txt` | 1 min |
| D04-012 | pid_max, number of visible processes and /proc mount options. | CMD `cat /proc/sys/kernel/pid_max; echo; ls -d /proc/[0-9]* \| wc -l; echo; grep -E 'hidepid\|subset' /proc/mounts \|\| echo 'proc mounted without hidepid'` | - | - | `proc-visibility.txt` | 30s |
| D04-013 | File locks held by processes. | CMD `cat /proc/locks; echo; lslocks -o COMMAND,PID,TYPE,SIZE,MODE,M,START,END,PATH 2>&1` | `lslocks` | - | `file-locks.txt` | 30s |
| D04-014 | SysV IPC objects, POSIX shared memory and message queues. | CMD `lsipc 2>&1; echo; cat /proc/sysvipc/shm 2>/dev/null; ls -la --time-style=full-iso /dev/shm /dev/mqueue 2>&1` | `lsipc` | - | `ipc-shared-memory.txt` | 30s |
| D04-015 | CPU/memory consumers at collection time. | CMD `top -b -n 1 2>&1 \| head -n 80` | - | - | `top.txt` | 1 min |

## D05 Network

Output folder `05_network/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D05-001 | Start a short packet capture on all interfaces in the background (default 60 s, max 200000 packets / 1 GB). *(off with `--no-pcap`; sensitive; changes: Puts interfaces in promiscuous mode for the capture window.)* | FUNC `pcap_start` | `tcpdump` | - | `pcap` | 30s |
| D05-002 | Every TCP/UDP socket with owning process, timers and TCP info. | CMD `ss -tunapeoi 2>&1` | `ss` | - | `ss-all-sockets.txt` | 1 min |
| D05-003 | Unix sockets, packet sockets and raw sockets. | CMD `ss -xapne 2>&1; echo; ss -0apn 2>&1; echo; ss -wapn 2>&1` | `ss` | - | `ss-unix-packet-raw.txt` | 1 min |
| D05-004 | Second socket listing with BusyBox netstat (cross-check with ss). | CMD `netstat -anpe 2>&1` | - | - | `netstat.txt` | 1 min |
| D05-005 | Raw kernel socket and routing tables. | COPY /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 /proc/net/raw /proc/net/raw6 /proc/net/unix /proc/net/packet /proc/net/arp /proc/net/route … | - | - | `-` | 1 min |
| D05-006 | Interfaces, addresses, link details and counters. | CMD `ip -d -s addr show 2>&1; echo; ip -d -s link show 2>&1` | `ip` | - | `ip-addr-link.txt` | 30s |
| D05-007 | Policy routing rules and all routing tables. | CMD `ip rule show 2>&1; echo; ip -6 rule show 2>&1; echo; ip route show table all 2>&1; echo; ip -6 route show table all 2>&1` | `ip` | - | `ip-rules-routes.txt` | 30s |
| D05-008 | ARP/NDP neighbour cache. | CMD `ip neigh show 2>&1; echo; ip -6 neigh show 2>&1; echo; arp -an 2>&1` | `ip` | - | `neighbours-arp.txt` | 30s |
| D05-009 | Tunnels, IPsec state, network namespaces, bridges. *(sensitive)* | CMD `ip tunnel show 2>&1; ip -d link show type vxlan 2>&1; ip -d link show type gre 2>&1; ip xfrm state 2>&1; ip xfrm policy 2>&1; ip netns list 2>&1; bridge link 2>&1; bridg…` | `bridge`, `ip` | - | `tunnels-xfrm-bridges.txt` | 30s |
| D05-010 | WireGuard interfaces, peers, endpoints, last handshake. | CMD `srv wg show all 2>&1` | - | wg | `wireguard.txt` | 20s |
| D05-011 | Name resolution configuration. | COPY /etc/resolv.conf /run/systemd/resolve/resolv.conf /run/systemd/resolve/stub-resolv.conf /etc/hosts /etc/host.conf /etc/nsswitch.conf /etc/hostname /e… | - | - | `-` | 1 min |
| D05-012 | systemd-resolved state: DNS servers per link, cache statistics. | CMD `srv resolvectl status 2>&1; srv resolvectl statistics 2>&1` | - | resolvectl | `resolvectl.txt` | 30s |
| D05-013 | Dump DNS caches that exist on the host (systemd-resolved via SIGUSR1 to journal, nscd, dnsmasq stats). *(changes: systemd-resolved writes its cache to the journal (one log entry).)* | FUNC `dns_cache_dump` | `c0f-copy`, `pgrep`, `pkill` | journalctl, nscd, resolvectl, unbound-control | `dns-cache` | 1 min |
| D05-014 | Network configuration of every network stack (ifupdown, netplan, NetworkManager, RHEL scripts, systemd-networkd). *(sensitive)* | COPY /etc/network /etc/netplan /etc/NetworkManager /etc/sysconfig/network-scripts /etc/sysconfig/network /etc/systemd/network /etc/wicked /etc/netctl /etc… | - | - | `-` | 2 min |
| D05-015 | NetworkManager runtime state. | CMD `srv nmcli -t general status 2>&1; srv nmcli -t connection show 2>&1; srv nmcli -t device show 2>&1` | - | nmcli | `nmcli.txt` | 30s |
| D05-016 | Interfaces in promiscuous mode and processes with packet sockets. | CMD `for i in /sys/class/net/*; do f=$(cat "$i/flags" 2>/dev/null); [ -n "$f" ] && [ $(( f & 0x100 )) -ne 0 ] && echo "PROMISC ${i##*/} flags=$f"; done; echo 'packet sockets …` | - | - | `promiscuous-sniffers.txt` | 30s |
| D05-017 | Connection tracking table (recent and current flows seen by netfilter). | CMD `cat /proc/net/nf_conntrack 2>/dev/null \| head -n 100000 \|\| echo 'nf_conntrack not available'` | - | - | `conntrack.txt` | 30s |
| D05-018 | NFS/SMB exports and mounts (exportfs, showmount, nfsstat, /proc/fs/nfsd). | FUNC `nfs_state` | - | exportfs, nfsstat, showmount, smbstatus | `nfs` | 1 min |
| D05-019 | VPN configurations (OpenVPN, IPsec, WireGuard, PPP, tinc, ZeroTier, Tailscale). *(sensitive)* | COPY /etc/openvpn /etc/ipsec.conf /etc/ipsec.d /etc/strongswan /etc/swanctl /etc/wireguard /etc/xl2tpd /etc/ppp /etc/tinc /etc/zerotier /var/lib/zerotier-… | - | - | `-` | 1 min |
| D05-020 | IP forwarding and all network kernel parameters. | CMD `cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding 2>&1; sysctl -a 2>/dev/null \| grep -E '^net\.'` | `sysctl` | - | `net-sysctl.txt` | 30s |
| D05-099 | Stop the background capture started by D05-001 and record its statistics. *(off with `--no-pcap`)* | FUNC `pcap_stop` | - | - | `pcap-stop.txt` | 5 min |

## D06 Firewall and hardening

Output folder `06_firewall_hardening/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D06-001 | iptables/ip6tables rules with packet counters, legacy backend. | CMD `xtables-legacy-multi iptables-save -c 2>&1; echo '#### ip6tables (legacy)'; xtables-legacy-multi ip6tables-save -c 2>&1` | `xtables-legacy-multi` | - | `iptables-legacy-save.txt` | 1 min |
| D06-002 | iptables/ip6tables/arptables/ebtables rules via the nft backend. | CMD `xtables-nft-multi iptables-save -c 2>&1; echo '#### ip6tables (nft)'; xtables-nft-multi ip6tables-save -c 2>&1; echo '#### arptables'; xtables-nft-multi arptables-save 2…` | `nft`, `xtables-nft-multi` | - | `iptables-nft-save.txt` | 1 min |
| D06-003 | Complete nftables ruleset with rule handles. | CMD `nft -a list ruleset 2>&1` | `nft` | - | `nft-ruleset.txt` | 1 min |
| D06-004 | Contents of all IP sets. | CMD `ipset list 2>&1` | `ipset` | - | `ipset.txt` | 1 min |
| D06-005 | UFW status and rules as UFW sees them. | CMD `srv ufw status verbose 2>&1; echo; srv ufw show added 2>&1` | - | ufw | `ufw-status.txt` | 30s |
| D06-006 | firewalld runtime zones, services, ports, rich and direct rules. | CMD `srv firewall-cmd --state 2>&1; srv firewall-cmd --get-active-zones 2>&1; srv firewall-cmd --list-all-zones 2>&1; srv firewall-cmd --direct --get-all-rules 2>&1` | - | firewall-cmd | `firewalld.txt` | 1 min |
| D06-007 | Persistent firewall configuration of every common firewall front-end. | COPY /etc/ufw /etc/firewalld /etc/sysconfig/iptables /etc/sysconfig/ip6tables /etc/sysconfig/iptables-config /etc/iptables /etc/nftables.conf /etc/nftable… | - | - | `-` | 2 min |
| D06-008 | fail2ban jails, banned IPs and configuration; CrowdSec decisions when present. | FUNC `fail2ban_state` | `ip`, `sqlite3` | cscli, fail2ban-client | `fail2ban` | 2 min |
| D06-009 | fail2ban and CrowdSec configuration and databases. | COPY /etc/fail2ban /var/lib/fail2ban /etc/crowdsec /var/lib/crowdsec/data/crowdsec.db | - | - | `-` | 1 min |
| D06-010 | All kernel parameters. | CMD `sysctl -a 2>/dev/null` | `sysctl` | - | `sysctl-all.txt` | 1 min |
| D06-011 | Persistent kernel parameter files. | COPY /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d /lib/sysctl.d | - | - | `-` | 1 min |
| D06-012 | SELinux mode and policy (from sysfs, plus sestatus/semodule when installed). | CMD `echo "selinuxfs=$(ls -d /sys/fs/selinux 2>/dev/null)"; echo "enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)"; echo "policyvers=$(cat /sys/fs/selinux/policyvers 2>/de…` | - | getenforce, semodule, sestatus | `selinux.txt` | 30s |
| D06-013 | SELinux configuration and locally added policy modules (priority 400). | COPY /etc/selinux/config /etc/selinux/semanage.conf /etc/selinux/targeted/active/modules/400 /etc/selinux/targeted/contexts/files/file_contexts.local /var… | - | - | `-` | 2 min |
| D06-014 | AppArmor state and loaded profiles with their mode. | CMD `echo "apparmor_enabled=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"; cat /sys/kernel/security/apparmor/profiles 2>/dev/null; srv aa-status 2>&1` | - | aa-status | `apparmor.txt` | 30s |
| D06-015 | AppArmor profiles on disk. | COPY /etc/apparmor /etc/apparmor.d | - | - | `-` | 1 min |
| D06-016 | TCP wrappers and host access/login policy files. | COPY /etc/hosts.allow /etc/hosts.deny /etc/securetty /etc/security/access.conf /etc/security/limits.conf /etc/security/limits.d /etc/security/faillock.con… | - | - | `-` | 1 min |
| D06-017 | Traffic control queues and filters (including eBPF classifiers). | CMD `for d in $(ls /sys/class/net); do echo "== $d"; srv tc qdisc show dev "$d" 2>&1; srv tc filter show dev "$d" ingress 2>&1; done` | - | tc | `tc-qdisc-filters.txt` | 1 min |
| D06-018 | IPv6 enablement and per-interface IPv4 security switches (rp_filter, redirects, source routing). | CMD `ip -6 addr show 2>&1 \| head -n 5; cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null; grep -r '' /proc/sys/net/ipv4/conf/all/ 2>/dev/null` | `ip` | - | `ip-stack-hardening.txt` | 30s |

## D07 Accounts and authentication

Output folder `07_accounts_auth/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D07-001 | Who is logged in right now: utmp parsed by c0f-logins, logind sessions, SSH/xrdp/VNC sessions, TTYs of running shells. | FUNC `sessions_now` | `c0f-logins`, `ps` | loginctl | `sessions` | 1 min |
| D07-002 | The server's own who/w/last/lastb output (glibc), as a cross-check of the C0F parser. | CMD `srv who -a 2>&1; echo; srv w 2>&1; echo; srv last -F -w -x 2>&1 \| head -n 5000; echo; srv lastb -F -w 2>&1 \| head -n 5000` | - | last, lastb, w, who | `server-who-w-last.txt` | 30s |
| D07-010 | Parse wtmp/btmp/utmp (all rotations, also .gz), lastlog and faillog with c0f-logins (glibc layout, libc-independent). | FUNC `logins_parse` | `c0f-logins` | - | `logins` | 5 min |
| D07-011 | Raw binary login records (utmp/wtmp/btmp, lastlog, faillog, wtmpdb, lastlog2, faillock). | COPY /var/run/utmp /run/utmp /var/log/wtmp* /var/log/btmp* /var/log/lastlog /var/log/faillog /var/lib/wtmpdb /var/lib/lastlog /var/log/tallylog /var/run/f… | - | - | `-` | 5 min |
| D07-012 | Login history from wtmpdb (replacement of wtmp on newer distros), read from a copy. | CMD `for db in /var/lib/wtmpdb/wtmp.db; do [ -f "$db" ] && { cp "$db" "$C0F_TMP/wtmpdb.copy" && sqlite3 -readonly -header -separator "$(printf '\t')" "$C0F_TMP/wtmpdb.copy" "…` | `sqlite3` | - | `logins/wtmpdb.tsv` | 1 min |
| D07-013 | Last login per user from the lastlog2 database. | CMD `lastlog2 -d /var/lib/lastlog/lastlog2.db 2>&1` | `lastlog2` | - | `logins/lastlog2.txt` | 1 min |
| D07-014 | systemd-logind sessions and users, including lingering users. | CMD `srv loginctl list-sessions --no-pager 2>&1; srv loginctl list-users --no-pager 2>&1; for s in $(srv loginctl list-sessions --no-legend 2>/dev/null \| awk '{print $1}'); d…` | - | loginctl | `loginctl.txt` | 30s |
| D07-020 | Account, password-hash, group and privilege files (with their backup copies -). *(sensitive)* | COPY /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- /etc/group /etc/group- /etc/gshadow /etc/gshadow- /etc/subuid /etc/subgid /etc/sudoers /etc/sudoers… | - | - | `-` | 1 min |
| D07-021 | Build accounts/users.csv, groups.csv and findings.txt from passwd/shadow/group/sudoers, login records and home folders. *(sensitive)* | DERIVED `users_table` | `docker`, `ps` | - | `accounts` | 2 min |
| D07-022 | Second view of accounts with password state from util-linux lslogins (kit). *(sensitive)* | CMD `lslogins -a -o USER,UID,GECOS,HOMEDIR,SHELL,NOLOGIN,PWD-LOCK,PWD-EMPTY,PWD-DENY,PWD-METHOD,GROUP,GID,SUPP-GROUPS,PWD-WARN,PWD-CHANGE,PWD-MIN,PWD-MAX,PWD-EXPIR 2>&1` | `lslogins` | - | `accounts/lslogins.txt` | 1 min |
| D07-023 | Accounts from network directories (LDAP/SSSD/AD/NIS) through the server's NSS (static kit tools cannot load NSS modules). | CMD `srv getent passwd 2>&1; echo '####'; srv getent group 2>&1` | - | getent | `accounts/getent-nss.txt` | 30s |
| D07-024 | PAM stack, directory/Kerberos configuration, polkit rules. *(sensitive)* | COPY /etc/pam.d /etc/pam.conf /etc/security /etc/sssd /etc/krb5.conf /etc/krb5.conf.d /etc/krb5.keytab /etc/ldap /etc/openldap /etc/nslcd.conf /etc/samba/… | - | - | `-` | 2 min |
| D07-025 | List every PAM module referenced, with path, hash, owning package path and timestamps; flag modules outside standard folders. | FUNC `pam_modules_check` | - | - | `pam-modules.txt` | 2 min |
| D07-030 | SSH server/client configuration and root's SSH folder (host private keys included: sensitive). *(sensitive)* | COPY /etc/ssh /etc/ssh/sshd_config.d /etc/ssh/ssh_config.d /root/.ssh /etc/ssh/ssh_known_hosts /etc/ssh/moduli | - | - | `-` | 2 min |
| D07-031 | Copy ~/.ssh of every account (authorized_keys, known_hosts, config, rc, keys) and list running ssh-agent sockets. *(sensitive)* | FUNC `ssh_user_files` | `c0f-copy` | - | `ssh-users` | 5 min |
| D07-032 | Fingerprint every SSH key on the host (host keys, user keys, authorized_keys) with c0f-sshkey: type, bits, SHA256/MD5, passphrase or not, options. *(sensitive)* | FUNC `ssh_key_inventory` | `c0f-sshkey` | - | `ssh-keys.tsv` | 5 min |
| D07-033 | Effective sshd configuration after includes and defaults. | CMD `srv sshd -T 2>&1` | - | sshd | `sshd-effective-config.txt` | 1 min |
| D07-034 | List and copy .rhosts, .shosts, hosts.equiv and shosts.equiv files. *(sensitive)* | FUNC `rhosts_check` | - | - | `rhosts.txt` | 1 min |
| D07-035 | sudo 'lectured' markers (users who ran sudo at least once) and sudo I/O logs. | COPY /var/lib/sudo/lectured /var/db/sudo/lectured /var/log/sudo-io /var/log/sudo.log /var/log/sudo-logsrvd | - | - | `-` | 1 min |

## D08 Persistence

Output folder `08_persistence/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D08-001 | All cron and at schedules, system and per user. | COPY /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /etc/anacrontab /etc/cron.allow /etc/cr… | - | - | `-` | 2 min |
| D08-002 | Pending at jobs with their command (end of each job script). | CMD `srv atq 2>&1; for j in $(srv atq 2>/dev/null \| awk '{print $1}'); do echo "== at job $j"; srv at -c "$j" 2>&1 \| tail -n 40; done` | - | at, atq | `at-queue.txt` | 30s |
| D08-003 | All systemd timers with next/last run and the unit they trigger. | CMD `srv systemctl list-timers --all --no-pager 2>&1` | - | systemctl | `systemd-timers.txt` | 1 min |
| D08-004 | Every systemd unit, drop-in, generator and preset (system and user). | COPY /etc/systemd /run/systemd/system /run/systemd/transient /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late /usr/lib/syst… | - | - | `-` | 5 min |
| D08-005 | Per-user systemd units (~/.config/systemd/user) and lingering users. | FUNC `user_systemd_units` | `c0f-copy` | - | `user-units` | 5 min |
| D08-006 | SysV, OpenRC, Upstart, runit, s6, supervisord and monit start-up scripts. | COPY /etc/init.d /etc/rc.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rcS.d /etc/rc.local /etc/rc.d/rc.local /etc/l… | - | - | `-` | 2 min |
| D08-007 | System-wide shell start-up files, environment, X session scripts, autostart and MOTD scripts. | COPY /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/bash_completion.d /etc/environment /etc/zsh /etc/zshrc /etc/zprofile /etc/zshenv /etc/z… | - | - | `-` | 2 min |
| D08-008 | Copy every hidden file in the top level of each home folder and the usual config folders (.config/autostart, .local/bin, .bashrc.d). *(sensitive)* | FUNC `user_dotfiles` | `c0f-copy` | - | `user-dotfiles` | 5 min |
| D08-009 | Dynamic loader preload and search path configuration. | COPY /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.cache | - | - | `-` | 1 min |
| D08-010 | Read /etc/ld.so.preload several ways (stat, direct read, listing) and scan process environments for LD_PRELOAD/LD_LIBRARY_PATH. | FUNC `ld_preload_check` | - | - | `ld-preload-check.txt` | 1 min |
| D08-011 | Kernel modules loaded at boot and module options/aliases. | COPY /etc/modules /etc/modules-load.d /usr/lib/modules-load.d /lib/modules-load.d /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d /etc/modprobe.conf | - | - | `-` | 2 min |
| D08-012 | udev rules. | COPY /etc/udev/rules.d /usr/lib/udev/rules.d /lib/udev/rules.d /run/udev/rules.d /etc/udev/udev.conf | - | - | `-` | 2 min |
| D08-013 | Hooks executed by other programs: logrotate postrotate, apt/dnf hooks and plugins, network dispatcher scripts, kernel/initramfs hooks. | COPY /etc/logrotate.conf /etc/logrotate.d /etc/apt/apt.conf.d /etc/yum/pluginconf.d /etc/dnf/plugins /usr/lib/yum-plugins /usr/lib/python3*/site-packages/… | - | - | `-` | 2 min |
| D08-014 | D-Bus services/policies and desktop autostart folders. | COPY /etc/dbus-1 /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /etc/xdg /usr/share/gnome-shell/extensions | - | - | `-` | 2 min |
| D08-015 | Boot loader configuration. | COPY /etc/default/grub /etc/default/grub.d /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI /boot/loader /etc/grub.d /etc/kernel/cmdline /etc/syscon… | - | - | `-` | 2 min |
| D08-016 | Registered binfmt_misc handlers. | CMD `for f in /proc/sys/fs/binfmt_misc/*; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done` | - | - | `binfmt-misc.txt` | 30s |
| D08-017 | lsattr scan of system and persistence folders for immutable (i) or append-only (a) files. | FUNC `immutable_attr_scan` | `lsattr` | - | `immutable-append-only.txt` | 10 min |
| D08-018 | Find git repositories under web roots, /opt, /srv, /home, /root and copy their hooks and config (+ git status/reflog files). | FUNC `git_hooks_scan` | `c0f-copy` | - | `git-hooks` | 10 min |

## D09 Services

Output folder `09_services/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D09-001 | All loaded units with load/active/sub state. | CMD `srv systemctl list-units --all --no-pager --no-legend --full 2>&1` | - | systemctl | `systemctl-units.txt` | 1 min |
| D09-002 | Every unit file with enabled/disabled/static/masked state. | CMD `srv systemctl list-unit-files --no-pager --no-legend 2>&1` | - | systemctl | `systemctl-unit-files.txt` | 1 min |
| D09-003 | For every service: systemctl show (ExecStart, FragmentPath, DropInPaths, MainPID, timestamps, User) and systemctl cat. | FUNC `systemd_service_details` | - | systemctl | `services-detail` | 10 min |
| D09-004 | Build services.csv: one row per service/daemon with state, start time, main PID, binary, binary SHA-256, user, unit file times (when installed/enabled), owning package, origin. | DERIVED `services_table` | - | rpm | `services.csv` | 15 min |
| D09-005 | Listening sockets whose process is not part of any service unit / init script. | FUNC `listeners_without_service` | `docker`, `ss` | - | `listeners-without-service.txt` | 2 min |
| D09-006 | Service state from SysV/OpenRC/Upstart/runit tools. | CMD `srv service --status-all 2>&1; srv chkconfig --list 2>&1; srv rc-status -a 2>&1; srv rc-update show -v 2>&1; srv initctl list 2>&1; srv sv status /var/service/* 2>&1` | - | chkconfig, initctl, rc-status, rc-update, service, sv | `non-systemd-services.txt` | 1 min |
| D09-007 | Failed units and default target/runlevel. | CMD `srv systemctl --failed --all --no-pager 2>&1; echo; srv systemctl get-default 2>&1; srv runlevel 2>&1` | - | runlevel, systemctl | `failed-units-target.txt` | 1 min |

## D10 Software and packages

Output folder `10_software/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D10-001 | Installed packages with version, architecture, install time, vendor/packager and signature (dpkg, rpm, apk, pacman, zypper, xbps, portage, nix, ...). | FUNC `packages_list` | - | apt, dnf, nix-env, nix-store, opkg, pacman, rpm, xbps-query, yum | `packages` | 15 min |
| D10-002 | Build software.csv: name, version, arch, install time, last change, how installed (repo/local file/manual), source repo, who installed (when logged). | DERIVED `software_table` | - | - | `software.csv` | 15 min |
| D10-003 | Package manager logs (install/upgrade/remove history), installer logs. | COPY /var/log/dpkg.log* /var/log/apt /var/log/yum.log* /var/log/dnf.log* /var/log/dnf.rpm.log* /var/log/dnf.librepo.log* /var/log/hawkey.log* /var/log/zyp… | - | - | `-` | 30 min |
| D10-004 | Raw package databases (dpkg, rpm, yum/dnf/dnf5 history, apk, pacman, zypp, xbps, portage, snapd, flatpak). | COPY /var/lib/dpkg/status /var/lib/dpkg/status-old /var/lib/dpkg/diversions /var/lib/dpkg/statoverride /var/lib/dpkg/info /var/lib/apt/extended_states /va… | - | - | `-` | 30 min |
| D10-005 | Transaction history: yum/dnf history database read with sqlite3 (copy, read-only) plus the server's yum/dnf history (cache-only), apt history, zypp history, pacman log, snap changes. | FUNC `pkg_history` | `sqlite3` | dnf, dnf5, flatpak, snap, yum, zypper | `package-history` | 10 min |
| D10-006 | Repository definitions and trusted signing keys of every package manager. *(sensitive)* | COPY /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/preferences /etc/apt/preferences.d /etc/apt/auth.c… | - | - | `-` | 10 min |
| D10-007 | GPG keys imported into the rpm database, with import time. | CMD `srv rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{INSTALLTIME:date}\t%{SUMMARY}\n' 2>&1` | - | rpm | `rpm-imported-keys.txt` | 1 min |
| D10-008 | Software outside the system package manager: pip (each interpreter, dist-info INSTALLER/direct_url.json), npm global, gem, cargo, go bin, composer, snap, flatpak, AppImage, conda. | FUNC `lang_packages` | `c0f-copy` | flatpak, snap | `language-packages` | 5 min |
| D10-009 | Executables in system and common folders that no package owns (dpkg/rpm/apk/pacman file lists), with hash, owner, times and ELF type. | FUNC `unpackaged_executables` | - | rpm | `unpackaged-executables.tsv` | 30 min |
| D10-010 | Package caches (downloaded packages, including ones already removed). | COPY /var/cache/apt/archives /var/cache/yum /var/cache/dnf /var/cache/zypp/packages /var/cache/pacman/pkg /var/cache/apk /etc/apk/cache /root/.cache/pip | - | - | `-` | 1 h |
| D10-020 | Verify installed files against the package database (dpkg md5sums computed by C0F, rpm -Va, pacman -Qkk, apk audit). | FUNC `package_integrity` | - | apk, dpkg, pacman, rpm | `package-integrity` | 2 h |

## D11 Filesystem and storage

Output folder `11_filesystem_storage/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D11-001 | Mount tables, partitions, RAID, encryption, export and automount configuration. | COPY /proc/mounts /proc/self/mountinfo /proc/partitions /proc/filesystems /proc/mdstat /proc/swaps /proc/diskstats /etc/fstab /etc/mtab /etc/crypttab /etc… | - | - | `-` | 1 min |
| D11-002 | Mount tree with options; space and inode usage per filesystem. | CMD `findmnt -A -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION,ID,PARENT 2>&1; echo; df -hT 2>&1; echo; df -i 2>&1` | `findmnt` | - | `mounts-usage.txt` | 1 min |
| D11-003 | Compare mountinfo of every process with PID 1 and list processes with a different mount view (outside containers). | FUNC `mount_namespace_diff` | `docker`, `findmnt` | - | `mount-namespaces.txt` | 2 min |
| D11-004 | Filesystem signatures, UUIDs, labels and partition tables. | CMD `blkid 2>&1; echo; fdisk -l 2>&1; echo; for d in /sys/block/*; do n=${d##*/}; case $n in loop*\|ram*) continue;; esac; echo "== $n"; sfdisk -d "/dev/$n" 2>&1; done` | `blkid`, `fdisk`, `sfdisk` | - | `partitions.txt` | 1 min |
| D11-005 | Per local filesystem: ext2/3/4 tune2fs -l and dumpe2fs -h (creation, last mount, last write, errors), XFS xfs_info, btrfs filesystem show/usage/subvolume list, ZFS zpool/zfs get all. | FUNC `fs_params` | `dumpe2fs`, `tune2fs` | btrfs, xfs_info, zfs | `fs-params` | 10 min |
| D11-006 | LVM report (pvs/vgs/lvs/pvdisplay/vgdisplay/lvdisplay --readonly, lvm config), device-mapper (dmsetup ls/table/status/info), LUKS status. | FUNC `lvm_state` | `blkid` | cryptsetup, dmsetup, lvm | `lvm` | 5 min |
| D11-007 | LVM metadata backups and archives. | COPY /etc/lvm/backup /etc/lvm/archive /etc/lvm/profile /run/lvm | - | - | `-` | 5 min |
| D11-008 | mdadm --detail --scan, multipath -ll, iscsiadm sessions, cryptsetup status, zpool status/history, btrfs subvolumes, quota, swapon --show. | FUNC `storage_extra` | - | arcstat, iscsiadm, mdadm, multipath, repquota, zfs, zpool | `storage-extra` | 5 min |
| D11-009 | SUID/SGID files, files with capabilities (getcap -r), world-writable folders without sticky bit, files without owner/group on local filesystems. | FUNC `suid_sgid_caps` | `getcap` | - | `special-permissions` | 30 min |
| D11-010 | getfacl -R and getfattr -d -m - on /etc, /usr/bin, /usr/sbin, /bin, /sbin, /root, /home, /var/spool/cron, web roots; SELinux labels. | FUNC `acl_xattr_scan` | `getfacl`, `getfattr` | - | `acl-xattr` | 30 min |
| D11-011 | Hidden files and folders (names starting with '.', '...', spaces) in system and temp folders; executables in /tmp, /var/tmp, /dev/shm, /run. | FUNC `hidden_files_scan` | - | - | `hidden-files` | 30 min |
| D11-012 | Copy files from RAM-backed folders (/dev/shm, /run excluding big runtime data, /tmp and /var/tmp when tmpfs) - lost at reboot. *(sensitive)* | FUNC `tmpfs_copy` | `c0f-copy` | - | `tmpfs-content` | 1 h |
| D11-013 | Files changed (mtime or ctime) within --since days in /etc, /usr, /bin, /sbin, /lib*, /opt, /root, /home, /var/www, /srv, /tmp, /var/tmp, /dev/shm, /boot. | FUNC `recent_changes` | - | - | `recent-changes` | 30 min |
| D11-014 | SHA-256 of every executable/shared library in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/*bin, /lib*/security and /usr/lib*/security. | FUNC `exec_hashes` | - | - | `executable-hashes.tsv` | 1 h |
| D11-015 | locate databases (snapshot of all file names at the last indexing). | COPY /var/lib/mlocate/mlocate.db /var/lib/plocate/plocate.db /var/cache/locate/locatedb /var/lib/slocate/slocate.db | - | - | `-` | 5 min |
| D11-020 | Full filesystem timeline: one row per file on every local filesystem (statx: atime, mtime, ctime, birth time, size, mode, owner, inode), plus a bodyfile for mactime/plaso. *(off with `--no-timeline`)* | FUNC `fs_timeline` | `c0f-copy` | - | `timeline` | 4 h |
| D11-021 | Filesystem metadata images: e2image for ext2/3/4 (all inodes, directories, journal, no file content), xfs_metadump/btrfs-image when the server has them; debugfs stats/lsdel/logdump summaries. *(off with `--no-e2image`)* | FUNC `fs_metadata_images` | `debugfs`, `dumpe2fs`, `e2image` | xfs_metadump | `fs-metadata` | 4 h |

## D12 Logs

Output folder `12_logs/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D12-001 | Complete /var/log tree (all rotations, .gz included, no size limit), excluding the C0F output folder. | COPY /var/log | - | - | `-` | 2 h |
| D12-002 | systemd journal files (persistent and volatile). | COPY /run/log/journal /var/log/journal | - | - | `-` | 1 h |
| D12-003 | Text export of the journal per boot (short-iso-precise), boot list, journal verification, disk usage. | FUNC `journal_export` | - | journalctl | `journal` | 1 h |
| D12-004 | Other log locations: /var/adm (older Unix/Linux), process accounting, rsyslog queues. | COPY /var/adm /var/run/log /run/log /var/account /var/log/account /var/log/pacct /var/spool/rsyslog | - | - | `-` | 30 min |
| D12-005 | Decoded process accounting (commands executed, user, tty, time). | CMD `for f in /var/account/pacct /var/log/account/pacct /var/log/pacct; do [ -f "$f" ] && { echo "== $f"; srv lastcomm -f "$f" 2>&1 \| head -n 200000; }; done` | - | lastcomm | `lastcomm.txt` | 2 min |
| D12-006 | Find and copy log files outside /var/log: paths named in rsyslog/syslog-ng/application configs and *.log files under /opt, /srv, /home, /root, /usr/local, /var/www, /var/lib. | FUNC `logs_outside_varlog` | `c0f-copy` | - | `logs-outside-varlog` | 20 min |
| D12-007 | Logging configuration: where logs go (local files, remote SIEM), retention, audit rules. | COPY /etc/rsyslog.conf /etc/rsyslog.d /etc/syslog.conf /etc/syslog-ng /etc/systemd/journald.conf /etc/systemd/journald.conf.d /etc/audit /etc/audisp /etc/… | - | - | `-` | 2 min |
| D12-008 | auditd status and active rules (auditctl -s/-l), plus aureport summaries (logins, executables, files, anomalies) from the copied audit logs. | FUNC `auditd_state` | - | auditctl, aureport, ausearch | `audit` | 10 min |
| D12-009 | Detect signs of log tampering: zero-size or recently created logs, rotation files larger than the current one, time gaps in wtmp/journal, non-text bytes in text logs, logs older than 'since' with recent change time. | FUNC `log_gap_check` | - | - | `log-integrity.txt` | 5 min |
| D12-010 | Summaries from auth.log/secure/journal: accepted/failed logins per user, source IP, method and key fingerprint; sudo commands; su; new users/groups; password changes. | FUNC `auth_summary` | `ip` | journalctl | `auth-summary` | 5 min |

## D13 Web servers

Output folder `13_web_servers/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D13-001 | Web server, proxy, PHP and TLS configuration (nginx, Apache, lighttpd, Caddy, HAProxy, Traefik, Varnish, Squid, Tomcat, PHP-FPM, ModSecurity, Let's Encrypt). *(sensitive)* | COPY /etc/nginx /usr/local/nginx/conf /usr/local/openresty/nginx/conf /opt/nginx/conf /etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/lighttpd /etc/c… | - | - | `-` | 5 min |
| D13-002 | Effective configuration as the server sees it: nginx -T, apachectl -S/-M/-t -D DUMP_INCLUDES. | FUNC `web_effective_config` | - | nginx, php | `effective-config` | 2 min |
| D13-003 | Parse access_log/error_log/CustomLog/ErrorLog/TransferLog from web server configs and copy logs located outside /var/log. | FUNC `web_logs_from_config` | `c0f-copy` | - | `logs-from-config` | 30 min |
| D13-004 | For every document root (from configs and /var/www, /srv/www, /usr/share/nginx/html): list + hash all files, copy scripts changed within --since days, all scripts in upload folders, credential files (.env, wp-config.php… *(sensitive)* | FUNC `webroot_inventory` | `c0f-copy` | - | `webroot` | 1 h |
| D13-005 | PHP session files (listing and content). *(sensitive)* | COPY /var/lib/php/sessions /var/lib/php5 /var/lib/php/session /tmp/sess_* | - | - | `-` | 30 min |
| D13-006 | Tomcat webapps list with hashes, recently deployed WAR files, catalina.out and access logs outside /var/log. | FUNC `tomcat_inventory` | `c0f-copy` | - | `tomcat` | 10 min |

## D14 Databases

Output folder `14_databases/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D14-001 | Database configuration files (MySQL/MariaDB, PostgreSQL incl. pg_hba.conf, Redis, MongoDB, Elasticsearch/OpenSearch, Cassandra, ClickHouse, InfluxDB, CouchDB, memcached, RabbitMQ, Kafka, Neo4j). *(sensitive)* | COPY /etc/mysql /etc/my.cnf /etc/my.cnf.d /etc/mariadb /etc/postgresql /var/lib/pgsql/data/*.conf /var/lib/pgsql/*/data/*.conf /var/lib/postgresql/*/main/… | - | - | `-` | 10 min |
| D14-002 | Locate and copy database logs from their configs: MySQL error/general/slow/audit logs and binary logs, PostgreSQL log_directory and pgAudit, Redis log, MongoDB log/audit, Elasticsearch logs; record whether general/audit… *(sensitive)* | FUNC `db_logs` | `c0f-copy` | - | `db-logs` | 2 h |
| D14-003 | Copy MySQL/MariaDB binary and relay logs (data change history). *(off with `--no-db-binlogs`; sensitive)* | FUNC `db_change_logs` | `c0f-copy` | - | `db-change-logs` | 4 h |
| D14-004 | Copy PostgreSQL WAL segments (pg_wal/pg_xlog). *(off with `--no-db-wal`; sensitive)* | FUNC `db_wal` | `c0f-copy` | - | `db-wal` | 4 h |
| D14-005 | Copy Redis AOF/RDB files, SQLite databases found in web roots and /opt, and list (name, size, hash) the data folders of other engines. *(off with `--no-db-data`; sensitive)* | FUNC `db_data_files` | `c0f-copy` | - | `db-data` | 4 h |
| D14-006 | Database client history and credential files of every user (.mysql_history, .psql_history, .rediscli_history, .dbshell, .mongosh, .my.cnf, .pgpass). *(sensitive)* | FUNC `db_client_files` | `c0f-copy` | - | `db-client-files` | 2 min |

## D15 Mail

Output folder `15_mail/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D15-001 | Mail server configuration (Postfix, Exim, Sendmail, Dovecot, DKIM, aliases, relays). *(sensitive)* | COPY /etc/postfix /etc/exim /etc/exim4 /etc/sendmail.cf /etc/mail /etc/dovecot /etc/opendkim /etc/aliases /etc/mailname /etc/ssmtp /etc/msmtprc /etc/nullm… | - | - | `-` | 10 min |
| D15-002 | Local mailboxes and mail queues (system and cron mails). *(sensitive)* | COPY /var/mail /var/spool/mail /var/spool/postfix /var/spool/exim /var/spool/exim4 /var/spool/mqueue /var/spool/clientmqueue | - | - | `-` | 1 h |
| D15-003 | Mail queue summary. | CMD `srv mailq 2>&1 \| head -n 5000` | - | mailq | `mailq.txt` | 1 min |
| D15-004 | ~/.forward, ~/.procmailrc, ~/.mailrc, ~/.muttrc of every user. *(sensitive)* | FUNC `user_mail_forward` | `c0f-copy` | - | `user-forwarding` | 2 min |

## D16 User applications

Output folder `16_applications/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D16-001 | Shell and REPL histories of every account incl. root and system accounts: bash, zsh, fish, ash, sh, ksh, tcsh, python, node, mysql, psql, sqlite, redis, less, vim (viminfo), wget-hsts; plus HISTFILE tampering checks. *(sensitive)* | FUNC `shell_histories` | `c0f-copy` | a | `shell-history` | 10 min |
| D16-002 | Per user: ~/.aws, ~/.azure, ~/.config/gcloud, ~/.kube, ~/.docker/config.json, ~/.gnupg (key list only), ~/.netrc, ~/.git-credentials, ~/.gitconfig, ~/.config/rclone, FileZilla, ~/.wget-hsts, ~/.npmrc, ~/.pypirc, recentl… *(sensitive)* | FUNC `user_app_artifacts` | `c0f-copy` | - | `user-apps` | 10 min |
| D16-003 | Remote access/transfer tools and their logs: AnyDesk, TeamViewer, RustDesk, NoMachine, Chrome Remote Desktop, ScreenConnect, Splashtop, ngrok, frp, chisel, cloudflared, tailscale, rclone, mega, gsutil. *(sensitive)* | FUNC `remote_access_tools` | `c0f-copy`, `ps` | - | `remote-access-tools` | 10 min |
| D16-004 | Configuration and logs of remote IDE servers and notebooks (~/.vscode-server, Jupyter runtime and config). *(sensitive)* | FUNC `dev_tool_artifacts` | `c0f-copy` | - | `dev-tools` | 5 min |
| D16-005 | tmux sessions and paste buffers per user socket; GNU screen sessions and /tmp/screen-exchange. *(sensitive; changes: Talks to the user's tmux server (read-only commands).)* | FUNC `tmux_screen_buffers` | `c0f-copy` | tmux | `multiplexer` | 2 min |

## D17 Desktop / GUI

Output folder `17_desktop_gui/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D17-001 | Detect graphical sessions: X11 sockets, Wayland sockets, display managers, xrdp/VNC/NoMachine, graphical.target, and the XAUTHORITY of each display. | FUNC `gui_detect` | `ps` | systemctl | `gui-sessions.txt` | 1 min |
| D17-002 | Clipboard of every X11 display (CLIPBOARD, PRIMARY, SECONDARY; every format; owner PID via X-Resource) with c0f-x11; Wayland via the server's wl-paste when present. *(off with `--no-clipboard`; sensitive; changes: Creates one temporary InputOnly window; asks the owning application for its dat…)* | FUNC `x11_clipboard` | `c0f-copy`, `c0f-x11` | wl-paste | `clipboard` | 5 min |
| D17-003 | Window tree of every X11 display: titles, classes, command, geometry, mapped state, owner PID (X-Resource and _NET_WM_PID). | FUNC `x11_windows` | `c0f-x11` | - | `windows` | 5 min |
| D17-004 | Screenshot (PNG) of every X11 display. *(off with `--no-screenshot`; sensitive)* | FUNC `x11_screenshots` | `c0f-x11` | - | `screenshots` | 5 min |
| D17-005 | Copy browser profiles' evidence files per user: Firefox (places, cookies, formhistory, logins, extensions), Chrome/Chromium/Brave/Edge/Opera/Vivaldi (History, Cookies, Login Data, Web Data, Preferences, Extensions list). *(sensitive)* | FUNC `browser_artifacts` | `c0f-copy` | - | `browsers` | 30 min |
| D17-006 | Per user: recently-used.xbel, Trash (files + info), thumbnail cache, autostart, GNOME/KDE MRU, keyrings/KWallet files, Thunderbird profile metadata, messengers (Slack/Telegram/Signal/Discord/Teams) config folders withou… *(sensitive)* | FUNC `desktop_user_artifacts` | `c0f-copy` | - | `desktop-users` | 30 min |
| D17-007 | Display manager, remote desktop, Bluetooth, Wi-Fi, removable media and printing artefacts. *(sensitive)* | COPY /var/log/Xorg.*.log /var/log/xrdp*.log /var/log/xrdp-sesman.log /var/log/lightdm /var/log/gdm /var/log/gdm3 /var/log/sddm.log /etc/xrdp /etc/gdm /etc… | - | - | `-` | 10 min |

## D18 Containers

Output folder `18_containers/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D18-001 | Detect container runtimes and sockets: Docker, Podman (root and rootless per user), containerd, CRI-O, LXC/LXD/Incus, systemd-nspawn; client/daemon versions. | FUNC `container_runtime_detect` | `crictl`, `ctr`, `docker`, `runc` | - | `runtimes.txt` | 2 min |
| D18-002 | Docker: version/info, containers incl. stopped (ps -a), inspect of every container/image/network/volume, logs with timestamps, diff, top, history --no-trunc of every image, events of the last --since days, compose label… *(sensitive)* | FUNC `docker_collect` | `c0f-copy`, `docker`, `jq`, `ps` | docker | `docker` | 1 h |
| D18-003 | For every running container (any runtime): network inside its namespace (ip addr/route/neigh, ss, iptables/nft) via nsenter -n, and key files read through /proc/<pid>/root (passwd, shadow, crontabs, shell histories, aut… *(sensitive)* | FUNC `container_namespaces` | `c0f-copy`, `docker`, `ip`, `nft`, `nsenter`, `ps`, `ss`, `xtables-legacy-multi`, `xtables-nft-multi` | - | `container-inside` | 1 h |
| D18-004 | Raw Docker/containerd/CRI-O/Podman configuration and per-container state files (config.v2.json, hostconfig.json, *-json.log). *(sensitive)* | COPY /var/lib/docker/containers /etc/docker /etc/containerd /etc/crio /etc/containers /var/lib/containers/storage/overlay-containers /etc/systemd/system/d… | - | - | `-` | 2 h |
| D18-005 | Search the filesystem for Dockerfile*, Containerfile*, *.dockerfile, docker-compose*/compose*.y?ml, .dockerignore, podman-compose, Helm charts, kustomization and Kubernetes manifests; copy them with the .env next to com… *(sensitive)* | FUNC `compose_dockerfiles_search` | `c0f-copy` | - | `build-files` | 1 h |
| D18-006 | Podman (root through the server's podman; rootless per user from storage files): ps -a, inspect, logs, images, volumes. *(sensitive)* | FUNC `podman_collect` | `c0f-copy`, `ps` | podman | `podman` | 1 h |
| D18-007 | containerd (ctr per namespace: containers, tasks, images, snapshots) and CRI (crictl ps -a, pods, inspect, logs, images); falls back to ctr where crictl is unavailable (armv7). *(sensitive)* | FUNC `containerd_cri_collect` | `crictl`, `ctr`, `ps` | - | `containerd-cri` | 30 min |
| D18-008 | LXC/LXD/Incus (list, info --show-log, config) and systemd-nspawn machines. | FUNC `lxc_nspawn_collect` | `c0f-copy` | incus, lxc, lxc-ls, machinectl | `lxc-nspawn` | 20 min |
| D18-020 | docker export of every container (including stopped ones) as tar (read-only operation). *(off with `--no-container-export`; sensitive)* | FUNC `container_exports` | `docker`, `ps` | docker | `exports` | 8 h |

## D19 Kubernetes

Output folder `19_kubernetes/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D19-001 | Detect Kubernetes on this node: kubelet, k3s, RKE2, microk8s, kind/minikube, static pod manifests, kubeconfig files usable for cluster-level reads. | FUNC `k8s_detect` | `kubectl`, `ps` | k3s, kubelet | `detect.txt` | 2 min |
| D19-002 | Node configuration: static pod manifests, kubelet config, CNI, k3s/RKE2/microk8s config (credentials included: sensitive). *(sensitive)* | COPY /etc/kubernetes /var/lib/kubelet/config.yaml /var/lib/kubelet/kubeadm-flags.env /var/lib/kubelet/pods /etc/cni /opt/cni/conf /var/lib/cni /etc/ranche… | - | - | `-` | 30 min |
| D19-003 | Pod and container logs on this node, API server audit logs when present. *(sensitive)* | COPY /var/log/pods /var/log/containers /var/log/kubernetes /var/log/kube-apiserver /var/lib/rancher/k3s/server/logs | - | - | `-` | 2 h |
| D19-004 | kubelet, container runtime and k3s/rke2 service logs from the journal; kube-proxy rules (iptables/ipvs). | FUNC `k8s_node_services` | `docker` | ipvsadm, journalctl | `node-services` | 10 min |
| D19-005 | Cluster-level read-only collection with a local admin kubeconfig (or --kubeconfig): get all/events -A -o yaml, nodes, namespaces, RBAC, service accounts, webhooks, CRDs, secrets (content), configmaps, pod logs incl. --p… *(sensitive; changes: Read requests are recorded in the API server audit log.)* | FUNC `k8s_cluster_collect` | `kubectl` | kubectl | `cluster` | 2 h |

## D20 Virtualization

Output folder `20_virtualization/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D20-001 | Virtual machines hosted here: libvirt (virsh list --all, dominfo, dumpxml, net-list), Proxmox (qm/pct list and config, pveversion, pvecm status, pvesm status, pveum user list), VirtualBox (list vms). | FUNC `virt_collect` | - | VBoxManage, pct, qm, virsh, virt-top | `hypervisors` | 10 min |
| D20-002 | Hypervisor configuration and logs (libvirt, Proxmox, VMware). *(sensitive)* | COPY /etc/libvirt /var/log/libvirt /etc/pve /var/log/pve /var/lib/vz/template /etc/vmware /var/log/vmware | - | - | `-` | 10 min |

## D21 Cloud agents

Output folder `21_cloud_agents/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D21-001 | Cloud-init and cloud agents (AWS SSM, Azure waagent, Google guest agent, Oracle, Hetzner, qemu guest agent) state and logs. *(sensitive)* | COPY /var/lib/cloud /etc/cloud /var/log/cloud-init.log /var/log/cloud-init-output.log /var/lib/amazon /var/log/amazon /etc/amazon /var/lib/waagent /var/lo… | - | - | `-` | 10 min |
| D21-002 | Cloud provider, instance id, region and image from local files only (no metadata service calls). | FUNC `cloud_identity` | - | - | `cloud-identity.txt` | 1 min |

## D22 Security tools

Output folder `22_security_tools/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D22-001 | Detect EDR/AV/HIDS agents and copy their status and logs: CrowdStrike (falconctl), Microsoft Defender (mdatp), SentinelOne, Sophos, Trend, Wazuh/OSSEC, osquery, ClamAV, Monarx, Elastic agent, Qualys, Tanium, Rapid7. *(sensitive)* | FUNC `security_agents` | `c0f-copy`, `ps` | clamconf, mdatp | `agents` | 15 min |
| D22-002 | HIDS/AV/integrity tool data: Wazuh/OSSEC logs, ClamAV logs, osquery, AIDE/Tripwire/Samhain databases and reports, rkhunter/chkrootkit/Lynis reports. *(sensitive)* | COPY /var/ossec/logs /var/ossec/queue/diff /var/log/clamav /var/lib/clamav/*.dat /var/log/osquery /etc/osquery /var/lib/aide /etc/aide /etc/aide.conf /var… | - | - | `-` | 30 min |

## D23 Kernel and rootkit checks

Output folder `23_kernel_rootkit/`

| ID | What is collected | How | Kit tools | Server programs (if present) | Output | Limit |
|---|---|---|---|---|---|---|
| D23-001 | Kernel taint flags, module loading lock, lockdown, Secure Boot, IMA/EVM, BPF restrictions. | CMD `echo "tainted=$(cat /proc/sys/kernel/tainted)"; echo "modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)"; echo "lockdown=$(cat /sys/kernel/security/l…` | - | - | `kernel-security-state.txt` | 30s |
| D23-002 | Loaded kernel modules from three sources. | CMD `echo '== /proc/modules'; cat /proc/modules; echo; echo '== lsmod'; lsmod 2>&1; echo; echo '== /sys/module (all, incl. built-in)'; ls /sys/module` | - | - | `modules.txt` | 30s |
| D23-003 | Per loaded module: modinfo fields, file path, SHA-256, signer, taint flags, whether the file belongs to the running kernel tree. | FUNC `module_details` | - | modinfo | `module-details.tsv` | 5 min |
| D23-004 | Compare /proc/modules, /sys/module/*/sections and kernel symbol owners in /proc/kallsyms. | FUNC `hidden_module_check` | - | - | `hidden-modules.txt` | 2 min |
| D23-005 | eBPF programs/maps/links (bpftool when present, otherwise /proc/*/fdinfo of bpf fds and /sys/fs/bpf pins), kprobes/uprobes/ftrace state from tracefs, kallsyms hash. | FUNC `ebpf_tracing` | - | bpftool | `ebpf-tracing` | 5 min |
| D23-006 | Compare process lists: /proc readdir, PID brute force (kill -0 / stat /proc/<pid> up to max PID), kit ps, server ps. | FUNC `cross_check_processes` | `ps` | ps | `cross-check-processes.txt` | 10 min |
| D23-007 | Compare listening/connected sockets from /proc/net/*, kit ss, kit netstat and the server's ss/netstat. | FUNC `cross_check_network` | `ss` | netstat, ss | `cross-check-network.txt` | 5 min |
| D23-008 | Compare directory listings of key folders (/etc, /usr/bin, /usr/sbin, /tmp, /dev/shm, /lib/modules) made by kit ls, kit find, getdents through BusyBox, and the server's ls. | FUNC `cross_check_files` | - | ls | `cross-check-files.txt` | 10 min |
| D23-009 | chkrootkit 0.58b (Debian patches) with the kit's tools only, expert output, plus its helpers chkproc, chkdirs, ifpromisc, chkutmp, chkwtmp, chklastlog (rebuilt for the glibc login record layout). | FUNC `run_chkrootkit` | `chkrootkit` | - | `chkrootkit` | 30 min |
| D23-010 | Kernel ring buffer with ISO timestamps (dmesg) and the kernel command line. | FUNC `kernel_logs_now` | `dmesg` | - | `kernel-messages.txt` | 2 min |

## Kit tools and the items that use them

All tools are statically linked and verified against the signed `SHA256SUMS` before use. BusyBox provides the shell (`c0f.sh`) and basic applets (`awk`, `sed`, `grep`, ...).

| Component | Version | Programs in `bin/<arch>/` | License |
|---|---|---|---|
| BusyBox | 1.38.0 + 1 C0F patch (build/patches: ash read after a trapped signal) | busybox (shell for c0f.sh + applets: awk, sed, grep, netstat, lsmod, ...) | GPL-2.0 |
| GNU coreutils | 9.12 | ls, stat, sha256sum, md5sum, date, timeout, cp, dd, sort, ... | GPL-3.0+ |
| GNU findutils | 4.11.0 | find, xargs | GPL-3.0+ |
| GNU tar | 1.35 | tar | GPL-3.0+ |
| util-linux | 2.42.4 | lsblk, findmnt, blkid, fdisk, sfdisk, lsns, nsenter, lslocks, lsipc, dmesg, lslogins, lastlog2, hwclock, script, flock, setsid, ionice, blockdev, wipefs | GPL-2.0+ and others |
| iproute2 | 7.3.0 | ip, ss, bridge | GPL-2.0 |
| e2fsprogs | 1.47.4 | debugfs, e2image, tune2fs, dumpe2fs, lsattr | GPL-2.0 |
| acl / attr | 2.4.0 / 2.6.0 | getfacl / getfattr | GPL-2.0+, LGPL-2.1+ |
| libcap | 2.78 | getcap | BSD-3-Clause or GPL-2.0 |
| iptables (+libmnl, libnftnl) | 1.8.13 | xtables-legacy-multi, xtables-nft-multi (iptables/ip6tables/arptables/ebtables save) | GPL-2.0 |
| nftables | 1.1.7 | nft | GPL-2.0 |
| ipset | 7.24 | ipset | GPL-2.0 |
| libpcap / tcpdump | 1.11.0 / 4.99.7 | tcpdump | BSD-3-Clause |
| procps-ng | 4.0.7 | ps, pgrep, pkill, pmap, free, uptime, vmstat, sysctl, pwdx | GPL-2.0+, LGPL-2.1+ |
| lsof | 4.99.7 | lsof | lsof license (BSD-like) |
| dmidecode | 3.7 | dmidecode | GPL-2.0+ |
| file | 5.48 | file + share/magic.mgc | BSD-2-Clause |
| SQLite | 3.54.0 | sqlite3 | Public domain |
| libsodium / minisign | 1.0.22 / 0.12 | minisign (kit signature check) | ISC |
| chkrootkit | 0.58b + Debian 0.58b-5 patches | chkrootkit/ (script + chkproc, chkdirs, ifpromisc, chkutmp, chkwtmp, chklastlog, strings-static) | BSD-2-Clause |
| C0F helpers | 1.0.0 | c0f-copy, c0f-logins, c0f-memdump, c0f-sshkey, c0f-x11 | MIT OR GPL-2.0-or-later (dual; LICENSES/C0F.txt) |
| docker CLI / containerd ctr / runc | 29.9.3 / 2.4.2 / 1.5.2 | docker, ctr, runc | Apache-2.0 |
| kubectl | 1.37.2 | kubectl | Apache-2.0 |
| crictl | 1.37.0 | crictl (x86_64, aarch64 only) | Apache-2.0 |
| jq | 1.8.2 | jq | MIT |
| AVML | 0.21.0 | avml (x86_64, aarch64 only) | MIT |
| 7-Zip | 26.05 | 7zzs | LGPL-2.1 + unRAR restriction |

| Tool | Used by items |
|---|---|
| `avml` | 1: D03-001 |
| `basename` | 2: D01-012, D04-008 |
| `blkid` | 2: D11-004, D11-006 |
| `blockdev` | 1: D03-020 |
| `bridge` | 1: D05-009 |
| `c0f-copy` | 33: D03-020, D05-013, D07-031, D08-005, D08-008, D08-018, D10-008, D11-012, D11-020, D12-006, D13-003, D13-004, D13-006, D14-002, D14-003, D14-004, D14-005, D14-006, D15-004, D16-001, D16-002, D16-003, D16-004, D16-005, D17-002, D17-005, D17-006, D18-002, D18-003, D18-005, D18-006, D18-008, D22-001 |
| `c0f-logins` | 2: D07-001, D07-010 |
| `c0f-memdump` | 2: D03-010, D03-011 |
| `c0f-sshkey` | 1: D07-032 |
| `c0f-x11` | 3: D17-002, D17-003, D17-004 |
| `cat` | 63: D01-001, D01-003, D01-005, D01-007, D01-008, D01-009, D01-010, D01-012, D01-015, D02-002, D02-003, D02-006, D02-010, D03-001, D03-002, D03-010, D03-011, D04-004, D04-005, D04-007, D04-008, D04-010, D04-011, D04-012, D04-013, D04-014, D05-001, D05-016, D05-017, D05-018, D05-020, D05-099, D06-012, D06-014, D06-018, D07-001, D07-021, D07-031, D07-034, D08-010, D08-016, D09-003, D09-005, D10-002, D10-005, D10-008, D11-003, D12-009, D12-010, D13-003, D13-004, D14-002, D14-003, D14-005, D16-001, D18-002, D18-003, D21-002, D23-001, D23-002, D23-003, D23-005, D23-006 |
| `chkrootkit` | 1: D23-009 |
| `chmod` | 2: D04-005, D04-008 |
| `cp` | 7: D06-008, D07-012, D09-004, D10-001, D10-005, D10-009, D10-020 |
| `crictl` | 2: D18-001, D18-007 |
| `ctr` | 2: D18-001, D18-007 |
| `cut` | 48: D01-003, D02-004, D03-001, D03-010, D03-011, D03-020, D04-004, D04-005, D04-008, D05-099, D06-008, D07-010, D07-021, D07-025, D07-031, D07-034, D08-005, D09-003, D09-004, D10-002, D10-005, D10-008, D10-009, D10-020, D11-005, D11-006, D11-009, D11-011, D11-013, D11-014, D11-020, D11-021, D13-004, D16-005, D17-002, D18-001, D18-002, D18-003, D18-005, D18-006, D18-007, D18-008, D18-020, D19-005, D20-001, D22-001, D23-003, D23-004 |
| `date` | 17: D01-014, D02-001, D02-010, D03-001, D04-004, D05-001, D05-013, D05-099, D07-021, D10-001, D10-002, D10-005, D10-007, D10-008, D11-013, D13-004, D18-002 |
| `dd` | 5: D03-011, D03-020, D08-010, D14-002, D14-003 |
| `debugfs` | 1: D11-021 |
| `df` | 10: D03-001, D03-010, D03-020, D04-008, D05-001, D11-002, D11-005, D11-021, D18-002, D18-020 |
| `dmesg` | 1: D23-010 |
| `dmidecode` | 1: D01-006 |
| `docker` | 8: D07-021, D09-005, D11-003, D18-001, D18-002, D18-003, D18-020, D19-004 |
| `du` | 3: D10-008, D14-005, D18-001 |
| `dumpe2fs` | 3: D01-014, D11-005, D11-021 |
| `e2image` | 1: D11-021 |
| `env` | 1: D01-005 |
| `fdisk` | 1: D11-004 |
| `file` | 10: D02-004, D03-020, D07-010, D07-032, D10-001, D10-009, D10-020, D12-006, D12-009, D16-001 |
| `find` | 22: D02-004, D07-032, D08-010, D08-018, D10-008, D10-009, D11-009, D11-011, D11-013, D11-014, D12-006, D12-009, D13-003, D13-004, D13-006, D14-005, D16-002, D16-004, D17-005, D18-005, D23-005, D23-008 |
| `findmnt` | 2: D11-002, D11-003 |
| `free` | 8: D01-009, D03-001, D03-010, D03-020, D04-008, D05-001, D11-021, D18-020 |
| `getcap` | 1: D11-009 |
| `getfacl` | 1: D11-010 |
| `getfattr` | 1: D11-010 |
| `head` | 33: D01-005, D01-008, D01-014, D02-004, D02-010, D02-011, D04-015, D05-009, D05-017, D06-012, D06-018, D07-002, D07-025, D08-010, D08-018, D09-004, D10-005, D10-008, D11-003, D11-009, D12-005, D12-009, D14-002, D14-005, D15-003, D16-004, D18-001, D18-005, D21-002, D23-001, D23-003, D23-005, D23-006 |
| `hwclock` | 2: D02-006, D02-010 |
| `id` | 22: D01-015, D02-010, D07-031, D07-032, D07-034, D08-005, D08-008, D10-005, D12-009, D14-006, D15-004, D16-001, D16-002, D16-003, D16-004, D17-002, D17-005, D17-006, D18-001, D18-002, D18-003, D18-006 |
| `ip` | 8: D05-006, D05-007, D05-008, D05-009, D06-008, D06-018, D12-010, D18-003 |
| `ipset` | 1: D06-004 |
| `jq` | 1: D18-002 |
| `kubectl` | 2: D19-001, D19-005 |
| `lastlog2` | 1: D07-013 |
| `ls` | 39: D01-005, D01-013, D01-014, D03-001, D03-002, D04-004, D04-009, D04-012, D04-014, D06-012, D06-017, D07-014, D07-025, D07-031, D07-032, D07-034, D08-010, D09-004, D10-001, D10-008, D10-009, D10-020, D11-006, D11-010, D12-010, D13-006, D14-002, D14-003, D16-005, D17-001, D17-005, D18-002, D18-003, D18-006, D18-007, D21-002, D23-001, D23-002, D23-008 |
| `lsattr` | 1: D08-017 |
| `lsblk` | 1: D01-011 |
| `lsipc` | 1: D04-014 |
| `lslocks` | 1: D04-013 |
| `lslogins` | 1: D07-022 |
| `lsns` | 1: D04-009 |
| `lsof` | 1: D04-006 |
| `md5sum` | 1: D10-020 |
| `mkdir` | 28: D03-020, D04-004, D05-013, D07-021, D07-031, D08-005, D08-018, D09-004, D10-001, D10-005, D10-008, D10-009, D10-020, D11-012, D13-006, D14-002, D14-004, D14-005, D16-005, D17-002, D18-002, D18-003, D18-006, D18-007, D18-008, D19-005, D20-001, D22-001 |
| `nft` | 3: D06-002, D06-003, D18-003 |
| `nsenter` | 1: D18-003 |
| `pgrep` | 1: D05-013 |
| `pkill` | 1: D05-013 |
| `printf` | 116: D01-003, D01-004, D01-005, D01-007, D01-014, D02-001, D02-005, D02-007, D02-008, D02-010, D02-011, D03-001, D03-010, D03-011, D03-020, D03-022, D04-004, D04-005, D04-008, D04-010, D05-010, D05-012, D05-013, D05-015, D05-018, D06-005, D06-006, D06-008, D06-012, D06-014, D06-017, D07-001, D07-002, D07-010, D07-012, D07-014, D07-021, D07-023, D07-025, D07-031, D07-032, D07-033, D07-034, D08-002, D08-003, D08-005, D08-008, D08-017, D08-018, D09-001, D09-002, D09-003, D09-004, D09-005, D09-006, D09-007, D10-001, D10-002, D10-005, D10-007, D10-008, D10-009, D10-020, D11-003, D11-005, D11-006, D11-008, D11-009, D11-010, D11-011, D11-013, D11-014, D11-020, D11-021, D12-003, D12-005, D12-006, D12-008, D12-009, D12-010, D13-002, D13-003, D13-004, D14-005, D14-006, D15-003, D15-004, D16-001, D16-002, D16-003, D16-004, D16-005, D17-001, D17-002, D17-003, D17-004, D17-005, D17-006, D18-001, D18-002, D18-003, D18-005, D18-006, D18-007, D18-008, D18-020, D19-004, D19-005, D20-001, D21-002, D22-001, D23-003, D23-005, D23-006, D23-007, D23-008 |
| `ps` | 15: D04-001, D04-002, D04-003, D07-001, D07-021, D16-003, D17-001, D18-002, D18-003, D18-006, D18-007, D18-020, D19-001, D22-001, D23-006 |
| `readlink` | 19: D01-003, D01-012, D01-015, D02-003, D02-004, D03-010, D03-011, D04-004, D04-005, D04-007, D04-008, D04-011, D09-004, D09-005, D11-003, D12-009, D16-001, D18-003, D23-005 |
| `runc` | 1: D18-001 |
| `setsid` | 1: D05-001 |
| `sfdisk` | 1: D11-004 |
| `sha256sum` | 18: D01-003, D01-013, D02-003, D02-004, D04-004, D04-005, D04-008, D05-099, D07-025, D09-004, D10-008, D10-009, D11-011, D11-014, D13-004, D13-006, D23-003, D23-004 |
| `sort` | 25: D01-014, D02-004, D07-025, D07-031, D07-032, D08-010, D09-003, D09-004, D10-001, D10-009, D11-003, D11-009, D11-013, D11-014, D12-010, D13-003, D13-004, D14-003, D18-002, D18-003, D18-005, D23-004, D23-006, D23-007, D23-008 |
| `split` | 6: D07-021, D08-017, D10-002, D10-020, D12-009, D23-007 |
| `sqlite3` | 3: D06-008, D07-012, D10-005 |
| `ss` | 5: D05-002, D05-003, D09-005, D18-003, D23-007 |
| `stat` | 28: D01-014, D03-011, D03-020, D04-001, D04-003, D04-004, D04-005, D04-008, D05-099, D07-021, D07-025, D08-010, D09-004, D10-008, D10-009, D11-011, D11-012, D11-014, D12-006, D12-009, D13-003, D13-004, D16-001, D17-001, D17-002, D17-003, D17-004, D18-005 |
| `sysctl` | 2: D05-020, D06-010 |
| `tail` | 13: D01-014, D04-004, D05-013, D08-002, D09-005, D11-003, D12-010, D14-002, D14-003, D14-005, D18-003, D23-006, D23-010 |
| `tcpdump` | 1: D05-001 |
| `test` | 2: D08-010, D18-002 |
| `timeout` | 1: D05-001 |
| `tr` | 55: D01-003, D01-005, D03-001, D03-010, D03-011, D03-020, D04-004, D04-005, D04-008, D04-010, D04-011, D05-013, D06-008, D07-001, D07-010, D07-021, D07-025, D07-031, D07-032, D08-010, D09-003, D09-004, D09-005, D10-005, D10-008, D10-009, D11-005, D11-006, D11-013, D11-020, D11-021, D12-003, D12-008, D12-009, D16-001, D16-005, D17-001, D17-002, D17-003, D17-004, D18-002, D18-003, D18-005, D18-007, D18-008, D18-020, D19-005, D20-001, D22-001, D23-001, D23-004, D23-005, D23-006, D23-007, D23-008 |
| `tune2fs` | 1: D11-005 |
| `uname` | 2: D01-001, D23-003 |
| `uniq` | 2: D08-010, D12-010 |
| `uptime` | 1: D02-002 |
| `vmstat` | 1: D01-009 |
| `wc` | 10: D04-005, D04-008, D04-012, D07-010, D10-008, D11-020, D12-009, D13-003, D13-004, D23-004 |
| `xargs` | 2: D07-032, D11-009 |
| `xtables-legacy-multi` | 2: D06-001, D18-003 |
| `xtables-nft-multi` | 2: D06-002, D18-003 |

Also in the kit (support programs, used by the collector itself or inside other tools): `7zzs`, `ionice`, `minisign`, `pmap`, `script`, `shred`, `wipefs`.

## Server programs C0F may call

Only when present on the examined system. They are not trusted: every use is logged per item and listed in `tools-used.csv` (with SHA-256); a crash is reported as `SERVER_TOOL_CRASHED`.

| Program | Items |
|---|---|
| `VBoxManage` | D20-001 |
| `a` | D16-001 |
| `aa-status` | D06-014 |
| `apk` | D02-011, D10-020 |
| `apt` | D10-001 |
| `arcstat` | D11-008 |
| `at` | D08-002 |
| `atq` | D08-002 |
| `auditctl` | D12-008 |
| `aureport` | D12-008 |
| `ausearch` | D12-008 |
| `been` | D02-010 |
| `bpftool` | D23-005 |
| `btrfs` | D11-005 |
| `chkconfig` | D09-006 |
| `chronyc` | D02-007 |
| `clamconf` | D22-001 |
| `coredumpctl` | D03-022 |
| `cryptsetup` | D11-006 |
| `cscli` | D06-008 |
| `dmsetup` | D11-006 |
| `dnf` | D10-001, D10-005 |
| `dnf5` | D10-005 |
| `docker` | D18-002, D18-020 |
| `dpkg` | D10-020 |
| `dpkg-query` | D02-011 |
| `exe` | D04-011 |
| `exportfs` | D05-018 |
| `fail2ban-client` | D06-008 |
| `firewall-cmd` | D06-006 |
| `flatpak` | D10-005, D10-008 |
| `getenforce` | D06-012 |
| `getent` | D07-023 |
| `hostnamectl` | D01-004 |
| `incus` | D18-008 |
| `initctl` | D09-006 |
| `ipvsadm` | D19-004 |
| `iscsiadm` | D11-008 |
| `journalctl` | D02-010, D05-013, D12-003, D12-010, D19-004 |
| `k3s` | D19-001 |
| `kubectl` | D19-005 |
| `kubelet` | D19-001 |
| `last` | D07-002 |
| `lastb` | D07-002 |
| `lastcomm` | D12-005 |
| `loginctl` | D07-001, D07-014 |
| `ls` | D23-008 |
| `lsb_release` | D01-004 |
| `lvm` | D11-006 |
| `lxc` | D18-008 |
| `lxc-ls` | D18-008 |
| `machinectl` | D18-008 |
| `mailq` | D15-003 |
| `mdadm` | D11-008 |
| `mdatp` | D22-001 |
| `modinfo` | D23-003 |
| `multipath` | D11-008 |
| `netstat` | D23-007 |
| `nfsstat` | D05-018 |
| `nginx` | D13-002 |
| `nix-env` | D10-001 |
| `nix-store` | D10-001 |
| `nmcli` | D05-015 |
| `nscd` | D05-013 |
| `ntpq` | D02-008 |
| `ntpstat` | D02-008 |
| `opkg` | D10-001 |
| `pacman` | D10-001, D10-020 |
| `pct` | D20-001 |
| `php` | D13-002 |
| `podman` | D18-006 |
| `ps` | D23-006 |
| `qm` | D20-001 |
| `rc-status` | D09-006 |
| `rc-update` | D09-006 |
| `repquota` | D11-008 |
| `resolvectl` | D05-012, D05-013 |
| `rpm` | D01-014, D02-011, D09-004, D10-001, D10-007, D10-009, D10-020 |
| `runlevel` | D09-007 |
| `semodule` | D06-012 |
| `service` | D09-006 |
| `sestatus` | D06-012 |
| `showmount` | D05-018 |
| `smbstatus` | D05-018 |
| `snap` | D10-005, D10-008 |
| `ss` | D23-007 |
| `sshd` | D07-033 |
| `sv` | D09-006 |
| `systemctl` | D08-003, D09-001, D09-002, D09-003, D09-007, D17-001 |
| `systemd-detect-virt` | D01-005 |
| `tc` | D06-017 |
| `timedatectl` | D02-005 |
| `tmux` | D16-005 |
| `ufw` | D06-005 |
| `unbound-control` | D05-013 |
| `virsh` | D20-001 |
| `virt-top` | D20-001 |
| `w` | D07-002 |
| `wg` | D05-010 |
| `who` | D07-002 |
| `wl-paste` | D17-002 |
| `xbps-query` | D10-001 |
| `xfs_info` | D11-005 |
| `xfs_metadump` | D11-021 |
| `yum` | D10-001, D10-005 |
| `zfs` | D11-005, D11-008 |
| `zpool` | D11-008 |
| `zypper` | D10-005 |
