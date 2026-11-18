# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D03 / D04 =======================
space_left_ok() {  # same rule as c0f.sh: on the examined system keep >=10% and >=2 GB free, on external media 512 MB
  _fk=$(df -Pk "$C0F_OUT" 2>/dev/null | awk 'NR==2{print $4" "$2}'); _f=${_fk% *}; _tt=${_fk#* }; [ -n "$_f" ] || return 0
  if [ "$OUT_EXTERNAL" = YES ]; then _m=524288; else _m=$((_tt/10)); [ "$_m" -lt 2097152 ] && _m=2097152; fi
  [ "$_f" -ge "$(( _m + ${1:-0} ))" ]
}
is_c0f_pid() { tr '\0' '\n' 2>/dev/null < "/proc/$1/environ" 2>/dev/null | grep -q "^C0F_TMP=$C0F_TMP\$"; }
ram_dump() {
  [ "$ARCH" = armv7 ] && { echo "AVML is not released for 32-bit ARM: RAM dump not possible with the kit"; return 15; }
  case " $C0F_BLOCKED_LIST " in *" avml "*) echo "kit avml failed verification/self-test: not used"; return 14;; esac
  mem=$(awk '/^MemTotal/{print $2}' /proc/meminfo)
  space_left_ok "$((mem + mem/10))" || { echo "not enough free space for a RAM image of ${mem} kB"; sub FAILED NO_SPACE "RAM ${mem} kB"; return 16; }
  echo "MemTotal=${mem} kB"; echo "lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null)"
  echo "start $(date -u +%FT%T.%NZ)"
  avml acquire "$ITEM_OUT/memory.lime" > "$ITEM_OUT/avml.log" 2>&1; rc=$?
  echo "end $(date -u +%FT%T.%NZ) rc=$rc"
  cat "$ITEM_OUT/avml.log"
  [ $rc = 0 ] && [ -s "$ITEM_OUT/memory.lime" ] && { ls -l "$ITEM_OUT/memory.lime"; return 0; }
  grep -iE 'error|caused|need|denied|lockdown' "$ITEM_OUT/avml.log" | tr '\n' ' ' | cut -c1-200 >&2; echo >&2
  grep -qiE "permission|denied|lockdown|not permitted|need CAP_|unable to read|no usable source|failed to read" "$ITEM_OUT/avml.log" && return 14
  return 1
}
# suspicious process selection shared by memory dumps and executable copies
suspicious_pids() {
  for p in /proc/[0-9]*; do pid=${p##*/}; [ "$pid" = 1 ] && continue
    is_c0f_pid "$pid" && continue
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    cmd=$(tr '\0' ' ' 2>/dev/null < "$p/cmdline" | cut -c1-200); comm=$(cat "$p/comm" 2>/dev/null)
    why=""
    case "$exe" in *' (deleted)') why="$why deleted-exe";; esac
    case "$exe" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/memfd:*|*/.*) why="$why exe-in-temp-memfd-or-hidden-path";; esac
    case "$exe" in /proc/*|'') why="$why exe-unusual";; esac
    # existence is checked inside the process's own root (containers, chroots), not on the host filesystem
    [ -e "/proc/$pid/root${exe% (deleted)}" ] || case "$why" in *deleted*) ;; *) why="$why exe-missing-on-disk";; esac
    case "$cmd" in '['*) why="$why fake-kernel-thread-name";; esac
    lp=$(tr '\0' '\n' 2>/dev/null < "$p/environ" | grep -m 1 '^LD_PRELOAD=' | cut -c12-200)
    [ -n "$lp" ] && why="$why LD_PRELOAD=$lp"
    [ -n "$why" ] && printf '%s\t%s\t%s\t%s\t%s\n' "$pid" "$comm" "$exe" "${why# }" "$cmd"
  done
}
proc_memdumps() {
  suspicious_pids > "$ITEM_OUT/selection.tsv"
  [ -s "$ITEM_OUT/selection.tsv" ] || { echo "no process matched the selection criteria"; rm -f "${ITEM_OUT:?}/selection.tsv"; return 10; }
  n=0; bad=0; : > "$C0F_TMP/pdump-groups"
  while IFS="$TAB" read -r pid comm exe why cmd; do
    # processes with the same executable and the same reason(s) (e.g. 40 browser content processes with one
    # LD_PRELOAD value) are dumped once: the first one represents the group, the others are listed as duplicates
    key="$exe|$why"; rep=$(awk -F'\t' -v k="$key" '$1==k{print $2; exit}' "$C0F_TMP/pdump-groups")
    if [ -n "$rep" ]; then sub SKIPPED DUPLICATE "pid $pid $comm: same executable and reason as pid $rep (dumped)"; continue; fi
    printf '%s\t%s\n' "$key" "$pid" >> "$C0F_TMP/pdump-groups"
    rss=$(awk '/^VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null)
    space_left_ok "$(( ${rss:-0} * 2 ))" || { sub SKIPPED NO_SPACE "pid $pid"; bad=1; continue; }
    c0f-memdump "$pid" "$ITEM_OUT/${pid}_$(safe "$comm")" 2>>"$ITEM_OUT/memdump.log"; rc=$?
    case $rc in 0) sub OK - "pid $pid $comm ($why)"; n=$((n+1));; 1) sub OK PARTIAL "pid $pid some regions unreadable"; n=$((n+1));;
      3) sub DENIED PERMISSION_DENIED "pid $pid"; bad=1;; *) sub FAILED EXIT_NONZERO "pid $pid rc=$rc"; bad=1;; esac
  done < "$ITEM_OUT/selection.tsv"
  echo "dumped $n process(es)"; [ $bad = 1 ] && return 13; return 0
}
shell_memory_history() {
  found=0
  for p in /proc/[0-9]*; do pid=${p##*/}; comm=$(cat "$p/comm" 2>/dev/null)
    case "$comm" in bash|zsh|sh|ash|dash|ksh|mksh|fish|tcsh|csh|busybox) ;; *) continue;; esac
    is_c0f_pid "$pid" && continue
    tty=$(readlink "$p/fd/0" 2>/dev/null); case "$tty" in /dev/pts/*|/dev/tty*) ;; *) continue;; esac
    user=$(stat -c %U "$p" 2>/dev/null); pre="$C0F_TMP/shm_$pid"
    c0f-memdump "$pid" "$pre" >/dev/null 2>&1 || { sub FAILED EXIT_NONZERO "pid $pid dump failed"; continue; }
    out="$ITEM_OUT/${pid}_$(safe "$user")_$(safe "${tty#/dev/}")_$comm.strings.txt"
    { echo "# pid=$pid user=$user tty=$tty comm=$comm cmdline=$(tr '\0' ' ' 2>/dev/null < "$p/cmdline")"
      echo "# printable strings (>=4 chars) from heap and anonymous rw regions; unsaved history lines are among them"
      awk -F'\t' 'NR>1 && $12 ~ /OK|PARTIAL/ && ($8=="[heap]" || ($8=="" && $4 ~ /^rw/)) {print $9" "$10}' "$pre.regions.tsv" | while read -r off len; do
        dd if="$pre.mem" bs=4096 skip=$((off/4096)) count=$((len/4096)) 2>/dev/null | strings -n 4; done | awk 'length($0)<400 && !seen[$0]++'
    } > "$out"
    rm -f "${pre:?}.mem" "${pre:?}.maps" "${pre:?}.regions.tsv" "${pre:?}.info.txt"; found=$((found+1)); sub OK - "pid $pid $comm $tty"
  done
  [ $found = 0 ] && { echo "no interactive shell running"; return 10; }; return 0
}
swap_copy() {
  awk 'NR>1{print $1" "$2" "$4}' /proc/swaps > "$ITEM_OUT/swaps.txt"
  [ -s "$ITEM_OUT/swaps.txt" ] || { rm -f "${ITEM_OUT:?}/swaps.txt"; echo "no active swap"; return 10; }
  bad=0
  while read -r dev typ used; do
    sz=$(( $(blockdev --getsize64 "$dev" 2>/dev/null || stat -c %s "$dev" 2>/dev/null || echo 0) / 1024 ))
    space_left_ok "$sz" || { sub SKIPPED NO_SPACE "$dev"; bad=1; continue; }
    o="$ITEM_OUT/$(safe "$dev").swap"
    if [ "$typ" = file ]; then cpo "$ITEM_OUT/file-copy" "$dev" && sub OK - "$dev"
    else dd if="$dev" of="$o" bs=4M conv=sparse 2>>"$ITEM_OUT/dd.log" && sub OK - "$dev" || { sub FAILED EXIT_NONZERO "$dev"; bad=1; }; fi
  done < "$ITEM_OUT/swaps.txt"
  [ $bad = 1 ] && return 13; return 0
}
proc_details() {
  HZ=100; bt=$(awk '/^btime/{print $2}' /proc/stat); cache="$C0F_TMP/exehash.cache"; : > "$cache"
  printf 'pid\tppid\tuid\tuser\tcomm\texe\texe_deleted\texe_sha256\tcwd\troot\tstart_utc\tthreads\tns_mnt\tns_net\tns_pid\tcgroup\tld_preload\tcmdline\n' > "$ITEM_OUT/summary.tsv"
  for p in /proc/[0-9]*; do pid=${p##*/}; d="$ITEM_OUT/$pid"; [ -d "$p" ] || continue; mk "$d"
    tr '\0' ' ' 2>/dev/null < "$p/cmdline" > "$d/cmdline.txt" 2>/dev/null
    tr '\0' '\n' 2>/dev/null < "$p/environ" > "$d/environ.txt" 2>/dev/null
    for f in status stat maps limits loginuid sessionid cgroup mountinfo wchan oom_score_adj personality timerslack_ns; do cat "$p/$f" > "$d/$f.txt" 2>/dev/null; done
    { for l in exe cwd root; do echo "$l -> $(readlink "$p/$l" 2>/dev/null)"; done; ls -l "$p/ns/" 2>/dev/null; } > "$d/links.txt"
    ls -l "$p/fd/" > "$d/fd.txt" 2>/dev/null; ls -l "$p/map_files/" > "$d/map_files.txt" 2>/dev/null
    for f in "$d"/*; do [ -s "$f" ] || rm -f "${f:?}"; done
    exe=$(readlink "$p/exe" 2>/dev/null); del=no; case "$exe" in *' (deleted)') del=yes;; esac
    key="$(stat -L -c '%d:%i:%Y' "$p/exe" 2>/dev/null)"; h=""
    if [ -n "$key" ]; then h=$(awk -v k="$key" '$1==k{print $2; exit}' "$cache"); [ -n "$h" ] || { h=$(sha "$p/exe"); echo "$key $h" >> "$cache"; }; fi
    st=$(cat "$p/stat" 2>/dev/null); rest=${st##*) }; set -- $rest
    ppid=$2; thr=${18}; stt=${20}; start=""; [ -n "$stt" ] && start=$(date -u -d "@$((bt + stt / HZ))" +%FT%TZ 2>/dev/null)
    uid=$(awk '/^Uid:/{print $2}' "$p/status" 2>/dev/null); user=$(awk -F: -v u="$uid" '$3==u{print $1; exit}' /etc/passwd)
    lp=$(grep -c '^LD_PRELOAD=' "$d/environ.txt" 2>/dev/null)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$ppid" "$uid" "$user" "$(cat "$p/comm" 2>/dev/null)" "$exe" "$del" "$h" \
      "$(readlink "$p/cwd" 2>/dev/null)" "$(readlink "$p/root" 2>/dev/null)" "$start" "$thr" "$(readlink "$p/ns/mnt" 2>/dev/null)" "$(readlink "$p/ns/net" 2>/dev/null)" \
      "$(readlink "$p/ns/pid" 2>/dev/null)" "$(tail -n 1 "$p/cgroup" 2>/dev/null)" "${lp:-0}" "$(cut -c1-500 "$d/cmdline.txt" 2>/dev/null | tr '\t' ' ')" >> "$ITEM_OUT/summary.tsv"
  done
  echo "note: start_utc assumes USER_HZ=100 (Linux default on all supported architectures)" >> "$ITEM_OUT/summary-notes.txt"
  return 0
}
proc_exe_copies() {
  printf 'pid\tcomm\texe\treason\tsha256\tsize\tfile\n' > "$ITEM_OUT/index.tsv"; n=0
  suspicious_pids | while IFS="$TAB" read -r pid comm exe why cmd; do
    f="$ITEM_OUT/${pid}_$(safe "$comm").bin"
    if cat "/proc/$pid/exe" > "$f" 2>/dev/null && [ -s "$f" ]; then chmod 600 "$f"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$comm" "$exe" "$why" "$(sha "$f")" "$(stat -c %s "$f")" "${f##*/}" >> "$ITEM_OUT/index.tsv"; sub OK - "pid $pid $exe"
    else rm -f "${f:?}"; sub FAILED EXIT_NONZERO "pid $pid cannot read exe"; fi
  done
  [ "$(wc -l < "$ITEM_OUT/index.tsv")" -gt 1 ] && return 0; rm -f "${ITEM_OUT:?}/index.tsv"; echo "no suspicious executable"; return 10
}
deleted_open_file_copies() {
  printf 'pid\tcomm\tfd\ttarget\tsize\tsha256\tfile\n' > "$ITEM_OUT/index.tsv"
  for p in /proc/[0-9]*; do pid=${p##*/}; is_c0f_pid "$pid" && continue
    for fd in "$p"/fd/*; do l=$(readlink "$fd" 2>/dev/null) || continue
      case "$l" in *' (deleted)') ;; *) continue;; esac
      case "$l" in /dev/*|/memfd:*|'anon_inode:'*) case "$l" in /memfd:*) ;; *) continue;; esac;; esac
      [ -f "$fd" ] || continue
      sz=$(stat -L -c %s "$fd" 2>/dev/null || echo 0); space_left_ok "$((sz/1024))" || { sub SKIPPED NO_SPACE "$pid fd ${fd##*/}"; continue; }
      f="$ITEM_OUT/${pid}_fd${fd##*/}_$(safe "$(basename "${l% (deleted)}")").bin"
      cat "$fd" > "$f" 2>/dev/null; chmod 600 "$f"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$(cat "$p/comm" 2>/dev/null)" "${fd##*/}" "$l" "$(stat -c %s "$f")" "$(sha "$f")" "${f##*/}" >> "$ITEM_OUT/index.tsv"
    done
  done
  [ "$(wc -l < "$ITEM_OUT/index.tsv")" -gt 1 ] && return 0; rm -f "${ITEM_OUT:?}/index.tsv"; return 10
}
kthread_check() {
  n=0
  for p in /proc/[0-9]*; do pid=${p##*/}; [ "$pid" = 2 ] && continue
    st=$(cat "$p/stat" 2>/dev/null); rest=${st##*) }; set -- $rest; ppid=$2
    cmd=$(tr '\0' ' ' 2>/dev/null < "$p/cmdline"); exe=$(readlink "$p/exe" 2>/dev/null); comm=$(cat "$p/comm" 2>/dev/null)
    if [ "$ppid" != 2 ] && { case "$cmd" in '['*']'*) true;; *) false;; esac; }; then
      echo "SUSPICIOUS pid=$pid ppid=$ppid comm=$comm cmdline=$cmd exe=$exe (bracketed name but not a child of kthreadd)"; n=$((n+1))
    elif [ "$ppid" = 2 ] && [ -n "$exe" ]; then echo "SUSPICIOUS pid=$pid child of kthreadd but has exe=$exe"; n=$((n+1)); fi
  done
  [ $n = 0 ] && echo "none found"; return 0
}
