# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D05 / D06 =======================
pcap_start() {
  case " $C0F_BLOCKED_LIST " in *" tcpdump "*) echo "kit tcpdump not usable"; return 14;; esac
  space_left_ok 1048576 || { echo "not enough space for a capture"; return 16; }
  sec=${C0F_PCAPSEC:-60}
  # -C 1000 caps the file at ~1 GB, -c caps packets; stops itself after $sec seconds
  setsid timeout "$sec" tcpdump -i any -n -s 0 -U -c 200000 -C 1000 -W 1 -w "$ITEM_OUT/capture.pcap" > "$ITEM_OUT/tcpdump.log" 2>&1 < /dev/null &
  echo $! > "$C0F_TMP/run/pcap.pid"; date -u +%s > "$C0F_TMP/run/pcap.start"
  echo "capture started for ${sec}s (pid $(cat "$C0F_TMP/run/pcap.pid")) on all interfaces at $(date -u +%FT%TZ)"
  return 0
}
pcap_stop() {
  [ -f "$C0F_TMP/run/pcap.pid" ] || { echo "no capture was started"; return 12; }
  pid=$(cat "$C0F_TMP/run/pcap.pid"); i=0
  while kill -0 "$pid" 2>/dev/null && [ $i -lt 240 ]; do sleep 1; i=$((i+1)); done
  kill "$pid" 2>/dev/null; sleep 1; rm -f "${C0F_TMP:?}/run/pcap.pid"
  d="$C0F_OUT/05_network/pcap"
  echo "capture window: started $(date -u -d @"$(cat "$C0F_TMP/run/pcap.start")" +%FT%TZ), stopped $(date -u +%FT%TZ)"
  cat "$d/tcpdump.log" 2>/dev/null
  for f in "$d"/capture.pcap*; do [ -f "$f" ] && echo "$f size=$(stat -c %s "$f") sha256=$(sha "$f")"; done
  return 0
}
dns_cache_dump() {
  n=0
  if has resolvectl && pgrep -x systemd-resolve >/dev/null 2>&1 || pgrep -x systemd-resolved >/dev/null 2>&1; then
    srv resolvectl statistics > "$ITEM_OUT/resolved-statistics.txt" 2>&1
    since=$(date '+%Y-%m-%d %H:%M:%S'); pkill -USR1 -x systemd-resolved 2>/dev/null; sleep 2
    srv journalctl -u systemd-resolved --no-pager -o short-iso-precise --since "$since" > "$ITEM_OUT/resolved-cache-dump.txt" 2>&1
    sub OK - "systemd-resolved cache dumped to journal (SIGUSR1)"; n=1
  fi
  if pgrep -x nscd >/dev/null 2>&1; then srv nscd -g > "$ITEM_OUT/nscd-stats.txt" 2>&1; cpo "$ITEM_OUT/nscd-db" /var/cache/nscd /var/db/nscd; n=1; fi
  if pgrep -x dnsmasq >/dev/null 2>&1; then
    since=$(date '+%Y-%m-%d %H:%M:%S'); pkill -USR1 -x dnsmasq 2>/dev/null; sleep 1
    { srv journalctl --no-pager -o short-iso-precise --since "$since" -t dnsmasq 2>/dev/null; grep -a dnsmasq /var/log/syslog /var/log/messages 2>/dev/null | tail -n 200; } > "$ITEM_OUT/dnsmasq-stats.txt"; n=1
    cpo "$ITEM_OUT/dnsmasq-leases" /var/lib/misc/dnsmasq.leases /var/lib/dnsmasq
  fi
  if pgrep -x unbound >/dev/null 2>&1 && has unbound-control; then srv unbound-control dump_cache > "$ITEM_OUT/unbound-cache.txt" 2>&1; n=1; fi
  [ $n = 0 ] && { echo "no local DNS cache service running"; return 12; }; return 0
}
nfs_state() {
  n=0
  [ -r /proc/fs/nfsd/exports ] && { cat /proc/fs/nfsd/exports > "$ITEM_OUT/nfsd-exports.txt"; n=1; }
  has exportfs && { srv exportfs -v > "$ITEM_OUT/exportfs.txt" 2>&1; n=1; }
  has showmount && { srv showmount -e localhost > "$ITEM_OUT/showmount-e.txt" 2>&1; srv showmount -a localhost > "$ITEM_OUT/showmount-a.txt" 2>&1; n=1; }
  has nfsstat && { srv nfsstat -a > "$ITEM_OUT/nfsstat.txt" 2>&1; n=1; }
  grep -E ' (nfs|nfs4|cifs|smb3|sshfs|fuse.sshfs|glusterfs|ceph|9p) ' /proc/mounts > "$ITEM_OUT/network-mounts.txt" 2>/dev/null && n=1 || rm -f "${ITEM_OUT:?}/network-mounts.txt"
  has smbstatus && { srv smbstatus > "$ITEM_OUT/smbstatus.txt" 2>&1; n=1; }
  [ $n = 0 ] && return 12; return 0
}
fail2ban_state() {
  if has fail2ban-client; then
    srv fail2ban-client status > "$ITEM_OUT/status.txt" 2>&1
    for j in $(sed -n 's/.*Jail list:[[:space:]]*//p' "$ITEM_OUT/status.txt" | tr ',' ' '); do srv fail2ban-client status "$j" > "$ITEM_OUT/jail_$(safe "$j").txt" 2>&1; done
  fi
  has cscli && { srv cscli decisions list -a > "$ITEM_OUT/crowdsec-decisions.txt" 2>&1; srv cscli alerts list > "$ITEM_OUT/crowdsec-alerts.txt" 2>&1; }
  for db in /var/lib/fail2ban/fail2ban.sqlite3; do [ -f "$db" ] && { cp "$db" "$C0F_TMP/f2b.db"; sqlite3 -readonly -header "$C0F_TMP/f2b.db" "SELECT jail,ip,datetime(timeofban,'unixepoch') AS ban_utc,bantime,bancount FROM bans ORDER BY timeofban;" > "$ITEM_OUT/ban-history.txt" 2>&1; rm -f "${C0F_TMP:?}/f2b.db"; }; done
  return 0
}
