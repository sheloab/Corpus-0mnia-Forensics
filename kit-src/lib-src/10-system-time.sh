# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D01 / D02 =======================
tz_identify() {
  [ -f /etc/localtime ] || { echo "/etc/localtime missing"; return 11; }
  l=$(readlink /etc/localtime 2>/dev/null); [ -n "$l" ] && echo "symlink: $l"
  h=$(sha /etc/localtime); echo "sha256 /etc/localtime: $h"
  [ -d /usr/share/zoneinfo ] || { echo "no /usr/share/zoneinfo to compare"; return 0; }
  m=$(find /usr/share/zoneinfo -type f -size -10k 2>/dev/null | while read -r z; do [ "$(sha "$z")" = "$h" ] && echo "${z#/usr/share/zoneinfo/}"; done | sort | head -n 30)
  if [ -n "$m" ]; then echo "matching zones:"; echo "$m"; else echo "no matching zone file (custom or tampered /etc/localtime)"; fi
}
time_change_evidence() {
  pat='Time has been changed|clock_settime|set-time|set-timezone|timedatectl set|hwclock --set|hwclock -w|date -s|date --set|adjtimex|System clock|time-change|Clock change detected|clock changed|Time jumped|selected source|time stepped|System clock wrong'
  echo "pattern: $pat"; echo
  for f in /var/log/syslog* /var/log/messages* /var/log/auth.log* /var/log/secure* /var/log/daemon.log* /var/log/kern.log* /var/log/audit/audit.log* /var/log/chrony/* ; do
    [ -f "$f" ] || continue
    # fixed-string pre-filter first (every pattern contains time/clock/date/"selected source"): ~5x faster on GB logs
    case "$f" in *.gz) zcat "$f" 2>/dev/null;; *) cat "$f" 2>/dev/null;; esac | grep -aiF -e time -e clock -e date -e 'selected source' | grep -aE "$pat" | sed "s|^|$f: |" | head -n 2000
  done
  has journalctl && srv journalctl --no-pager -o short-iso-precise -g 'Time has been changed|clock|time' 2>/dev/null | grep -aE "$pat" | head -n 5000 | sed 's|^|journal: |'
  each_home | while IFS="$TAB" read -r u id h s; do
    for hf in "$h"/.*history; do [ -f "$hf" ] && grep -aE '(^|[ ;|&])(date -s|date --set|hwclock|timedatectl set|tzselect|ln -s.*localtime)' "$hf" 2>/dev/null | sed "s|^|$hf: |"; done
  done
  return 0
}
os_profile_report() {
  echo "detected ID=$OS_ID VERSION_ID=$OS_VERSION_ID ID_LIKE=$OS_LIKE NAME=$OS_NAME"
  echo "profile=$OS_PROFILE family=$OS_FAMILY package_manager=$OS_PKG init_default=$OS_INIT in_container=$C0F_IN_CONTAINER"
  echo "pid1=$(readlink /proc/1/exe 2>/dev/null) comm=$(cat /proc/1/comm 2>/dev/null) systemd_running=$( [ -d /run/systemd/system ] && echo yes || echo no)"
  echo "profile note: $OS_PROFILE_NOTE"
  echo; echo "== commands the profile REQUIRES on this OS (missing = EXPECTED_BUT_MISSING)"
  miss=0
  for c in $OS_EXPECT_MUST; do p=$(srv_path "$c") && echo "present  $c  $p  sha256=$(sha "$p")" || { echo "MISSING  $c   <-- EXPECTED_BUT_MISSING"; sub "NOT FOUND" EXPECTED_BUT_MISSING "command $c"; miss=1; }; done
  echo; echo "== items present on a DEFAULT install of this OS (missing = informational)"
  for c in $OS_EXPECT_DEFAULT; do
    case "$c" in /*) [ -e "$c" ] && echo "present  $c" || echo "absent   $c (informational)";;
      *) p=$(srv_path "$c") && echo "present  $c  $p" || echo "absent   $c (informational)";; esac
  done
  [ $miss = 1 ] && return 13; return 0
}
virt_detect() {
  echo "== cpu hypervisor flag: $(grep -m1 -o hypervisor /proc/cpuinfo || echo none)"
  for f in sys_vendor product_name product_version board_vendor bios_vendor chassis_vendor product_uuid; do echo "dmi $f=$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done
  echo "== /sys/hypervisor/type: $(cat /sys/hypervisor/type 2>/dev/null)"
  echo "== systemd-detect-virt: $(srv systemd-detect-virt 2>/dev/null) container: $(srv systemd-detect-virt -c 2>/dev/null)"
  echo "== /proc/1/cgroup:"; cat /proc/1/cgroup 2>/dev/null
  echo "== container markers: $(ls -la /.dockerenv /run/.containerenv 2>/dev/null) env container=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep '^container=')"
  echo "== /proc/1/sched first line: $(head -n 1 /proc/1/sched 2>/dev/null)"
  echo "== WSL: $(grep -i microsoft /proc/version 2>/dev/null)"
  echo "== cloud markers:"
  for f in /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/bios_version /sys/class/dmi/id/chassis_asset_tag /var/lib/cloud/data/instance-id /var/lib/cloud/data/result.json; do [ -r "$f" ] && echo "$f: $(head -c 300 "$f")"; done
  return 0
}
os_install_time() {
  echo "== root filesystem creation time"
  dev=$(awk '$2=="/"{print $1}' /proc/mounts | tail -n 1)
  case "$dev" in /dev/*) dumpe2fs -h "$dev" 2>/dev/null | grep -E 'Filesystem created|Last mount time|Last write time|Lifetime writes';; esac
  echo "root inode times:"; stat / 2>/dev/null | grep -E 'Birth|Modify|Change'
  echo "== installer artefacts"
  ls -la --time-style=full-iso /var/log/installer /root/anaconda-ks.cfg /root/original-ks.cfg /var/log/anaconda /etc/machine-id 2>/dev/null
  echo "== oldest package install (dpkg info lists / rpm)"
  ls -lt --time-style=full-iso /var/lib/dpkg/info/*.list 2>/dev/null | tail -n 3
  has rpm && srv rpm -qa --qf '%{INSTALLTIME} %{NAME}-%{VERSION}\n' 2>/dev/null | sort -n | head -n 3 | while read -r t n; do echo "$(date -u -d @"$t" +%FT%TZ) $n"; done
  [ -f /var/log/pacman.log ] && head -n 3 /var/log/pacman.log
  echo "== /etc/ssh host key times (generated at install)"; ls -la --time-style=full-iso /etc/ssh/ssh_host_*key 2>/dev/null
  return 0
}
