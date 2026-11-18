# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D11 / D12 =======================
# local disk filesystems (mount point<TAB>device<TAB>type), no pseudo/network filesystems
local_fs() {
  awk '$3 ~ /^(ext2|ext3|ext4|xfs|btrfs|zfs|f2fs|jfs|reiserfs|vfat|exfat|ntfs|ntfs3|fuseblk|hfsplus|nilfs2|bcachefs)$/ {print $2"\t"$1"\t"$3}' /proc/mounts | sed 's/\\040/ /g' | awk -F'\t' '!seen[$2 $1]++'
}
mount_namespace_diff() {
  init=$(readlink /proc/1/ns/mnt)
  echo "PID 1 mount namespace: $init"; echo
  for p in /proc/[0-9]*; do n=$(readlink "$p/ns/mnt" 2>/dev/null) || continue; [ "$n" = "$init" ] && continue
    cg=$(tail -n 1 "$p/cgroup" 2>/dev/null); k=other; case "$cg" in *docker*|*containerd*|*kubepods*|*libpod*|*lxc*|*machine.slice*) k=container;; *.service) k=service-private-namespace;; esac
    printf '%s\t%s\t%s\t%s\n' "$n" "${p##*/}" "$(cat "$p/comm" 2>/dev/null)" "$k"
  done | sort | awk -F'\t' '{if($1!=last){print "== namespace "$1; last=$1} print "   pid "$2" "$3" ("$4")"}'
  echo; echo "== mounts visible to PID 1 that hide (cover) a non-empty directory of the underlying filesystem are not detectable here; see findmnt and mountinfo copies"
  echo "== mountinfo of PID 1 vs this collector:"; diff /proc/1/mountinfo /proc/self/mountinfo 2>&1 | head -n 50
  return 0
}
fs_params() {
  local_fs | while IFS="$TAB" read -r mp dev t; do
    o="$ITEM_OUT/$(safe "${dev#/dev/}")_$(safe "$mp").txt"
    { echo "== $dev mounted on $mp type $t"; df -hT "$mp"; df -i "$mp"
      case "$t" in
        ext2|ext3|ext4) dumpe2fs -h "$dev" 2>&1; echo; tune2fs -l "$dev" 2>&1;;
        xfs) srv xfs_info "$mp" 2>&1;;
        btrfs) srv btrfs filesystem show "$mp" 2>&1; srv btrfs filesystem usage "$mp" 2>&1; srv btrfs subvolume list -t "$mp" 2>&1;;
        zfs) srv zfs get all "$dev" 2>&1;;
      esac; } > "$o" 2>&1
  done
  return 0
}
lvm_state() {
  for c in "pvs -a -o +pv_uuid,dev_size,pv_mda_count" "vgs -o +vg_uuid,vg_mda_count" "lvs -a -o +devices,lv_uuid,origin,snap_percent,lv_time,lv_host,lv_role" "pvdisplay -m" "vgdisplay -v" "lvdisplay -m" "lvmconfig --type full" "lvm version"; do
    n=$(printf '%s' "$c" | cut -d' ' -f1)
    { echo "# lvm $c --readonly"; srv lvm $c --readonly 2>&1 || { echo "# retry without --readonly"; srv lvm $c 2>&1; }; } > "$ITEM_OUT/$n.txt"
  done
  { srv dmsetup ls --tree; echo; srv dmsetup table; echo; srv dmsetup status; echo; srv dmsetup info -c; } > "$ITEM_OUT/dmsetup.txt" 2>&1
  for m in /dev/mapper/*; do [ -e "$m" ] || continue; case "${m##*/}" in control) continue;; esac
    srv cryptsetup status "${m##*/}" 2>/dev/null | grep -q 'type:' && srv cryptsetup status "${m##*/}" > "$ITEM_OUT/cryptsetup-status-$(safe "${m##*/}").txt" 2>&1; done
  for d in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do srv cryptsetup luksDump "$d" > "$ITEM_OUT/luksDump-$(safe "${d#/dev/}").txt" 2>&1; done
  rm_empty "$ITEM_OUT"; return 0
}
storage_extra() {
  n=0
  has mdadm && [ -s /proc/mdstat ] && grep -q '^md' /proc/mdstat && { n=1; srv mdadm --detail --scan > "$ITEM_OUT/mdadm-scan.txt" 2>&1; for m in /dev/md[0-9]* /dev/md/*; do [ -e "$m" ] && srv mdadm --detail "$m"; done > "$ITEM_OUT/mdadm-detail.txt" 2>&1; }
  has multipath && { n=1; srv multipath -ll > "$ITEM_OUT/multipath.txt" 2>&1; }
  has iscsiadm && { n=1; srv iscsiadm -m session -P 3 > "$ITEM_OUT/iscsi-sessions.txt" 2>&1; srv iscsiadm -m node > "$ITEM_OUT/iscsi-nodes.txt" 2>&1; }
  has zpool && { n=1; srv zpool status -v > "$ITEM_OUT/zpool-status.txt" 2>&1; srv zpool history -il > "$ITEM_OUT/zpool-history.txt" 2>&1; srv zfs list -t all -o name,used,avail,mountpoint,creation > "$ITEM_OUT/zfs-list.txt" 2>&1; has arcstat && srv arcstat > "$ITEM_OUT/arcstat.txt" 2>&1; }
  has repquota && { n=1; srv repquota -a > "$ITEM_OUT/quota.txt" 2>&1; }
  swapon --show > "$ITEM_OUT/swapon.txt" 2>&1
  rm_empty "$ITEM_OUT"; [ $n = 0 ] && return 10; return 0
}
suid_sgid_caps() {
  local_fs | cut -f1 | sort -u > "$C0F_TMP/lfs"
  { printf 'path\tmode\towner\tgroup\tsize\tmtime\tctime\n'
    while read -r m; do find "$m" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\t%M\t%u\t%g\t%s\t%TY-%Tm-%Td %TT\t%CY-%Cm-%Cd %CT\n' 2>/dev/null; done < "$C0F_TMP/lfs"; } > "$ITEM_OUT/suid-sgid.tsv"
  while read -r m; do find "$m" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o -type f -print0 2>/dev/null | xargs -0 -r getcap 2>/dev/null; done < "$C0F_TMP/lfs" > "$ITEM_OUT/file-capabilities.txt"
  while read -r m; do find "$m" -xdev -type d -perm -0002 ! -perm -1000 -printf '%p\t%M\t%u\t%TY-%Tm-%Td %TT\n' 2>/dev/null; done < "$C0F_TMP/lfs" > "$ITEM_OUT/world-writable-dirs-no-sticky.tsv"
  while read -r m; do find "$m" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o \( -nouser -o -nogroup \) -printf '%p\t%U\t%G\t%M\t%TY-%Tm-%Td %TT\n' 2>/dev/null | head -n 100000; done < "$C0F_TMP/lfs" > "$ITEM_OUT/no-owner-or-group.tsv"
  while read -r m; do find "$m" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" -o -path /proc \) -prune -o -type f -perm -0002 -printf '%p\t%M\t%u\t%TY-%Tm-%Td %TT\n' 2>/dev/null | head -n 100000; done < "$C0F_TMP/lfs" > "$ITEM_OUT/world-writable-files.tsv"
  rm_empty "$ITEM_OUT"; return 0
}
acl_xattr_scan() {
  dirs="/etc /usr/bin /usr/sbin /bin /sbin /root /home /var/spool/cron /var/www /srv /opt"
  for d in $dirs; do [ -d "$d" ] || continue
    getfacl -R -s -p "$d" 2>/dev/null; done > "$ITEM_OUT/acl-non-default.txt"
  for d in $dirs; do [ -d "$d" ] || continue
    getfattr -R -h -d -m - --absolute-names "$d" 2>/dev/null; done > "$ITEM_OUT/xattr-all.txt"
  grep -B1 'security.capability' "$ITEM_OUT/xattr-all.txt" > "$ITEM_OUT/xattr-security-capability.txt" 2>/dev/null
  [ -d /sys/fs/selinux ] && for d in /usr/bin /usr/sbin /etc /tmp /var/tmp /dev/shm /var/www; do [ -d "$d" ] && ls -laZ "$d" 2>/dev/null; done > "$ITEM_OUT/selinux-labels.txt"
  rm_empty "$ITEM_OUT"; return 0
}
hidden_files_scan() {
  { printf 'path\ttype\tsize\tmode\towner\tmtime\tctime\n'
    find /etc /usr /bin /sbin /lib /lib64 /var /opt /srv /root /home /tmp /dev/shm /run /boot -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" -o -path /var/lib/docker -o -path /var/lib/containers \) -prune -o \( -name '.*' -o -name '* ' -o -name '...' -o -name '.. *' \) -printf '%p\t%y\t%s\t%M\t%u\t%TY-%Tm-%Td %TT\t%CY-%Cm-%Cd %CT\n' 2>/dev/null |
      awk -F'\t' '$1 !~ /\/home\/[^/]+\/\.[^/]*\/|\/root\/\.[^/]*\// || $1 ~ /\/\.\.\.|\/\. |\/\.\. /'; } > "$ITEM_OUT/hidden-entries.tsv"
  { printf 'path\tsize\tmode\towner\tmtime\tctime\tsha256\n'
    find /tmp /var/tmp /dev/shm /run /var/run /dev -xdev -type f -perm /111 2>/dev/null | while read -r f; do printf '%s\t%s\n' "$(stat -c '%n%t%s%t%A%t%U%t%y%t%z' "$f" | sed "s/%t/$TAB/g")" "$(sha "$f")"; done; } > "$ITEM_OUT/executables-in-temp-folders.tsv"
  { printf 'path\ttype\tsize\tmtime\n'; find /dev -xdev -type f -printf '%p\t%y\t%s\t%TY-%Tm-%Td %TT\n' 2>/dev/null; } > "$ITEM_OUT/regular-files-in-dev.tsv"
  return 0
}
tmpfs_copy() {
  n=0
  for d in /dev/shm /run/shm /run/user /run/lock /run/screen; do [ -d "$d" ] && { cpo "$ITEM_OUT" -R -x "$d"; n=1; }; done
  for d in /tmp /var/tmp; do case "$(stat -f -c %T "$d" 2>/dev/null)" in tmpfs|ramfs) cpo "$ITEM_OUT" -R -x "$d"; n=1;; esac; done
  [ -d /run ] && { cpo "$ITEM_OUT" -R -x -e /run/log/journal -e /run/containerd -e /run/docker -e /run/k3s -e /run/user -e /run/shm -e /run/udev/data /run; n=1; }
  [ $n = 0 ] && return 10; return 0
}
recent_changes() {
  since=$(date -d "@$(( $(date +%s) - C0F_SINCE*86400 ))" '+%Y-%m-%d %H:%M:%S')
  echo "window: files with mtime or ctime after $since (server local time), --since $C0F_SINCE days" > "$ITEM_OUT/README.txt"
  for d in /etc /usr /bin /sbin /lib /lib64 /opt /root /home /var/www /srv /tmp /var/tmp /dev/shm /boot /var/spool /usr/local; do
    [ -d "$d" ] || continue; [ -L "$d" ] && continue
    { printf 'ctime\tmtime\tsize\tmode\towner\tpath\n'
      find "$d" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o \( -newermt "$since" -o -newerct "$since" \) -printf '%CY-%Cm-%Cd %CT\t%TY-%Tm-%Td %TT\t%s\t%M\t%u\t%p\n' 2>/dev/null | sort -r; } > "$ITEM_OUT/$(safe "$d").tsv"
  done
  return 0
}
exec_hashes() {
  printf 'path\tsize\tmode\towner\tmtime\tctime\tsha256\n'
  find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/*-linux-gnu*/security /usr/lib/*-linux-gnu*/security -xdev -type f 2>/dev/null | sort -u | while read -r f; do
    printf '%s\t%s\n' "$(stat -c '%n%t%s%t%A%t%U%t%y%t%z' "$f" | sed "s/%t/$TAB/g")" "$(sha "$f")"
  done
  return 0
}
fs_timeline() {
  local_fs > "$C0F_TMP/lfs.tl"
  [ -s "$C0F_TMP/lfs.tl" ] || { echo "no local disk filesystem mounted"; return 11; }
  echo "# one TSV per filesystem (c0f-copy -n: statx incl. birth time) + bodyfile.txt for mactime/plaso (TSK 3.x format, epoch seconds)" > "$ITEM_OUT/README.txt"
  bad=0
  while IFS="$TAB" read -r mp dev t; do
    o="$ITEM_OUT/$(safe "${mp}").tsv"
    c0f-copy -n -R -x -e "$C0F_EXCL" -e "$C0F_KITDIR" -B "$ITEM_OUT/bodyfile.txt" -M "$o" "$mp" 2>>"$ITEM_OUT/errors.log" || bad=1
    sub OK - "$mp ($dev, $t): $(($(wc -l < "$o")-1)) entries"
  done < "$C0F_TMP/lfs.tl"
  return 0
}
fs_metadata_images() {
  n=0
  local_fs | while IFS="$TAB" read -r mp dev t; do
    case "$dev" in /dev/*) ;; *) continue;; esac
    b=$(safe "${dev#/dev/}")
    case "$t" in
      ext2|ext3|ext4)
        ic=$(dumpe2fs -h "$dev" 2>/dev/null | awk -F: '/^Inode count/{gsub(/ /,"",$2); print $2}'); is=$(dumpe2fs -h "$dev" 2>/dev/null | awk -F: '/^Inode size/{gsub(/ /,"",$2); print $2}')
        need=$(( ${ic:-0} * ${is:-256} / 1024 ))
        if space_left_ok "$need"; then
          e2image "$dev" "$ITEM_OUT/$b.e2i" > "$ITEM_OUT/$b.e2image.log" 2>&1 && sub OK - "e2image $dev" || sub FAILED EXIT_NONZERO "e2image $dev"
        else sub SKIPPED NO_SPACE "e2image $dev needs ~${need} kB"; fi
        { echo "== stats"; debugfs -R stats "$dev"; echo "== lsdel (deleted inodes still visible)"; debugfs -R lsdel "$dev"; } > "$ITEM_OUT/$b.debugfs-stats-lsdel.txt" 2>&1
        debugfs -R logdump "$dev" > "$ITEM_OUT/$b.debugfs-journal-logdump.txt" 2>&1 ;;
      xfs) if has xfs_metadump; then srv xfs_metadump -o -g "$dev" "$ITEM_OUT/$b.xfs-metadump" > "$ITEM_OUT/$b.xfs_metadump.log" 2>&1 && sub OK - "xfs_metadump $dev" || sub FAILED EXIT_NONZERO "xfs_metadump $dev (often refused on a read-write mounted filesystem)"; else sub "NOT FOUND" CMD_MISSING "xfs_metadump for $dev"; fi;;
      btrfs) sub SKIPPED NOT_APPLICABLE "btrfs-image needs an unmounted filesystem ($dev)";;
      *) sub SKIPPED NOT_APPLICABLE "no metadata imager for $t ($dev)";;
    esac
  done
  return 0
}
journal_export() {
  srv journalctl --list-boots --no-pager > "$ITEM_OUT/boots.txt" 2>&1
  srv journalctl --disk-usage > "$ITEM_OUT/disk-usage.txt" 2>&1
  srv journalctl --header --no-pager > "$ITEM_OUT/header.txt" 2>&1
  srv journalctl --verify > "$ITEM_OUT/verify.txt" 2>&1
  for b in $(awk '$1 ~ /^-?[0-9]+$/{print $1}' "$ITEM_OUT/boots.txt"); do
    srv journalctl -b "$b" --no-pager -o short-iso-precise > "$ITEM_OUT/boot_$(printf '%s' "$b" | tr -d '-' )$( [ "${b#-}" != "$b" ] && echo _minus).txt" 2>&1
  done
  [ -s "$ITEM_OUT/boots.txt" ] || srv journalctl --no-pager -o short-iso-precise > "$ITEM_OUT/all.txt" 2>&1
  return 0
}
logs_outside_varlog() {
  printf 'path\tsize\tmtime\thow_found\n' > "$ITEM_OUT/found.tsv"
  { grep -hE '^[^#$]*[[:space:]]-?/[^ ]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | awk '{print $NF}' | sed 's/^-//; s/;.*//' | awk '{print $0"\tsyslog-config"}'
    grep -hoE 'file\("[^"]+"' /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf 2>/dev/null | sed 's/file("//; s/"$//' | awk '{print $0"\tsyslog-ng-config"}'
    find /opt /srv /home /root /usr/local /var/www /var/lib /var/opt -xdev \( -path /var/lib/docker -o -path /var/lib/containers -o -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o -type f \( -name '*.log' -o -name '*.log.[0-9]*' -o -name '*_log' -o -name 'catalina.out*' -o -name '*.log.gz' \) -print 2>/dev/null | awk '{print $0"\tfilename-search"}'
  } | awk -F'\t' '$1 !~ /^\/var\/log\// && !seen[$1]++' > "$C0F_TMP/logs.out"
  n=0
  while IFS="$TAB" read -r f how; do [ -f "$f" ] || continue
    printf '%s\t%s\t%s\t%s\n' "$f" "$(stat -c %s "$f")" "$(stat -c %y "$f")" "$how" >> "$ITEM_OUT/found.tsv"; echo "$f"; n=1
  done < "$C0F_TMP/logs.out" > "$C0F_TMP/logs.list"
  [ -s "$C0F_TMP/logs.list" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/files" -e "$C0F_EXCL" -e "$C0F_KITDIR" -L "$C0F_TMP/logs.list" 2>>"$C0F_TMP/copy-stderr.log"
  return 0
}
auditd_state() {
  has auditctl && { srv auditctl -s > "$ITEM_OUT/status.txt" 2>&1; srv auditctl -l > "$ITEM_OUT/rules-active.txt" 2>&1; }
  if has aureport && [ -d /var/log/audit ]; then
    for r in "--summary" "-l" "-au" "-m" "-x --summary" "-f --summary" "-k --summary" "-n" "--failed" "-t" "-e --summary" "-a --summary"; do
      srv aureport -i $r > "$ITEM_OUT/aureport$(printf '%s' "$r" | tr ' -' '__').txt" 2>&1; done
  fi
  has ausearch && srv ausearch -i -m USER_LOGIN,USER_AUTH,USER_CMD,ADD_USER,DEL_USER,ADD_GROUP,USER_MGMT,CRED_ACQ -ts recent > "$ITEM_OUT/ausearch-recent-account-events.txt" 2>&1
  rm_empty "$ITEM_OUT"; return 0
}
log_gap_check() {
  echo "== zero-size log files"; find /var/log -xdev -type f -size 0 2>/dev/null
  echo; echo "== rotated log larger than 3x the current one (possible truncation of the current file)"
  for f in /var/log/*.1 /var/log/*/*.1; do [ -f "$f" ] || continue; c=${f%.1}; [ -f "$c" ] || continue
    a=$(stat -c %s "$f"); b=$(stat -c %s "$c"); [ "$b" -gt 0 ] && [ "$a" -gt $((b*3)) ] && [ "$a" -gt 1048576 ] && echo "$c ($b bytes) vs $f ($a bytes)"; done
  echo; echo "== text logs containing NUL bytes (zeroed regions)"
  for f in /var/log/*.log /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log /var/log/*/*.log; do [ -f "$f" ] || continue
    z=$(tr -dc '\000' < "$f" | wc -c); [ "$z" -gt 0 ] && echo "$f: $z NUL bytes"; done
  echo; echo "== logs whose change time is far newer than their modification time (timestamp manipulation or rename)"
  find /var/log -xdev -type f -printf '%T@ %C@ %p\n' 2>/dev/null | awk '{if ($2-$1 > 86400*7) printf "%s mtime=%d ctime=%d\n",$3,$1,$2}' | head -n 200
  echo; echo "== gaps longer than 12 hours between consecutive lines (syslog-style files)"
  for f in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do [ -f "$f" ] || continue
    awk -v f="$f" 'BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",m," "); for(i=1;i<=12;i++) M[m[i]]=i}
      { if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) { split(substr($1,1,19),a,/[-T:]/); t=((a[2]*31+a[3])*24+a[4])*60+a[5] }
        else if ($1 in M) { split($3,h,":"); t=((M[$1]*31+$2)*24+h[1])*60+h[2] } else next
        if (last && t-last > 720) printf "%s: gap of %d hours before line %d: %s\n", f, (t-last)/60, NR, substr($0,1,60); last=t }' "$f"
  done
  echo; echo "== login record anomalies (from D07-010)"; cat "$C0F_OUT/07_accounts_auth/logins/anomalies.tsv" 2>/dev/null | head -n 200
  echo; echo "== journal verification (from D12-003)"; grep -iE 'fail|corrupt|bad' "$C0F_OUT/12_logs/journal/verify.txt" 2>/dev/null | head -n 100
  echo; echo "== history files that are empty, missing for login users, or linked to /dev/null"
  each_home | while IFS="$TAB" read -r u id h s; do for f in "$h"/.bash_history "$h"/.zsh_history "$h"/.ash_history "$h"/.sh_history; do
    [ -L "$f" ] && echo "$f -> $(readlink "$f")"; [ -f "$f" ] && [ ! -s "$f" ] && echo "$f is EMPTY"; done; done
  return 0
}
auth_summary() {
  files=$(ls /var/log/auth.log* /var/log/secure* 2>/dev/null)
  cat_auth() {
    if [ -n "$files" ]; then for f in $files; do case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; done 2>/dev/null
    elif has journalctl; then srv journalctl --no-pager -o short-iso _COMM=sshd + _COMM=sudo + _COMM=su + _COMM=login + _COMM=useradd + _COMM=usermod + _COMM=passwd 2>/dev/null
    fi
  }
  cat_auth > "$C0F_TMP/auth.all"
  [ -s "$C0F_TMP/auth.all" ] || { echo "no authentication log found"; return 11; }
  { printf 'time\thost\tuser\tsource_ip\tport\tmethod\tkey\n'
    grep -a 'Accepted ' "$C0F_TMP/auth.all" | awk '{for(i=1;i<=NF;i++){ if($i=="Accepted"){m=$(i+1); u=$(i+3); ip=$(i+5); pt=$(i+7)} if($i ~ /^SHA256:|^MD5:/) k=$i } t=($1 ~ /T/)?$1:$1" "$2" "$3; h=($1 ~ /T/)?$2:$4; print t"\t"h"\t"u"\t"ip"\t"pt"\t"m"\t"k; k=""}'; } > "$ITEM_OUT/ssh-accepted.tsv"
  { printf 'count\tuser\tsource_ip\n'; grep -aE 'Failed (password|publickey)|Invalid user' "$C0F_TMP/auth.all" | awk '{u="?"; ip="?"; for(i=1;i<=NF;i++){ if($i=="for"){u=$(i+1); if(u=="invalid") u=$(i+3)} if($i=="from") ip=$(i+1); if($i=="user" && $(i-1)=="Invalid") u=$(i+1)} print u"\t"ip}' | sort | uniq -c | sort -rn | awk '{print $1"\t"$2"\t"$3}'; } > "$ITEM_OUT/ssh-failed-by-user-ip.tsv"
  grep -a 'sudo' "$C0F_TMP/auth.all" | grep -a 'COMMAND=' > "$ITEM_OUT/sudo-commands.txt"
  grep -aE ' su(\[[0-9]+\])?: | su: ' "$C0F_TMP/auth.all" > "$ITEM_OUT/su.txt"
  grep -aE 'useradd|userdel|usermod|groupadd|groupdel|passwd\[|chpasswd|new user|new group|delete user' "$C0F_TMP/auth.all" > "$ITEM_OUT/account-changes.txt"
  grep -aE 'session opened|session closed' "$C0F_TMP/auth.all" | awk '{print}' | tail -n 200000 > "$ITEM_OUT/sessions-opened-closed.txt"
  rm -f "${C0F_TMP:?}/auth.all"; rm_empty "$ITEM_OUT"; return 0
}
