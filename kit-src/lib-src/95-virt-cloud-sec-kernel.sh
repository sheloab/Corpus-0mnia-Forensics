# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D20 / D21 / D22 / D23 =======================
virt_collect() {
  if has virsh; then mk "$ITEM_OUT/libvirt"
    srv virsh list --all > "$ITEM_OUT/libvirt/list-all.txt" 2>&1; srv virsh net-list --all > "$ITEM_OUT/libvirt/net-list.txt" 2>&1; srv virsh pool-list --all > "$ITEM_OUT/libvirt/pool-list.txt" 2>&1
    for d in $(srv virsh list --all --name 2>/dev/null); do srv virsh dominfo "$d" > "$ITEM_OUT/libvirt/$(safe "$d").dominfo.txt" 2>&1; srv virsh dumpxml "$d" > "$ITEM_OUT/libvirt/$(safe "$d").xml" 2>&1; srv virsh snapshot-list "$d" > "$ITEM_OUT/libvirt/$(safe "$d").snapshots.txt" 2>&1; done
  fi
  if has qm || has pct; then mk "$ITEM_OUT/proxmox"
    for c in "pveversion -v" "qm list" "pct list" "pvecm status" "pvecm nodes" "pvesm status" "pveum user list" "pveum token list" "pvesubscription get" "ha-manager status"; do n=$(printf '%s' "$c" | tr ' ' '_'); srv $c > "$ITEM_OUT/proxmox/$n.txt" 2>&1; done
    for v in $(srv qm list 2>/dev/null | awk 'NR>1{print $1}'); do srv qm config "$v" > "$ITEM_OUT/proxmox/qm-$v.conf.txt" 2>&1; srv qm listsnapshot "$v" > "$ITEM_OUT/proxmox/qm-$v.snapshots.txt" 2>&1; done
    for v in $(srv pct list 2>/dev/null | awk 'NR>1{print $1}'); do srv pct config "$v" > "$ITEM_OUT/proxmox/pct-$v.conf.txt" 2>&1; done
  fi
  has VBoxManage && { srv VBoxManage list vms > "$ITEM_OUT/virtualbox-vms.txt" 2>&1; srv VBoxManage list runningvms >> "$ITEM_OUT/virtualbox-vms.txt" 2>&1; }
  has virt-top && srv virt-top -n 1 --stream > "$ITEM_OUT/virt-top.txt" 2>&1
  rm_empty "$ITEM_OUT"; return 0
}
cloud_identity() {
  v=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null); p=$(cat /sys/class/dmi/id/product_name 2>/dev/null); b=$(cat /sys/class/dmi/id/bios_version 2>/dev/null); a=$(cat /sys/class/dmi/id/chassis_asset_tag 2>/dev/null)
  echo "dmi: vendor=$v product=$p bios=$b asset_tag=$a uuid=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null)"
  case "$v $p $b" in *Amazon*|*amazon*) echo "provider: AWS";; *Google*) echo "provider: Google Cloud";; *Microsoft*) [ "$a" = 7783-7084-3265-9085-8269-3286-77 ] && echo "provider: Azure";; *Alibaba*) echo "provider: Alibaba Cloud";; *OpenStack*) echo "provider: OpenStack";; *DigitalOcean*) echo "provider: DigitalOcean";; *Hetzner*) echo "provider: Hetzner";; *Oracle*) echo "provider: Oracle Cloud (check)";; esac
  for f in /var/lib/cloud/data/instance-id /var/lib/cloud/data/previous-instance-id /var/lib/cloud/data/result.json /var/lib/cloud/data/status.json /var/lib/cloud/instance/datasource /run/cloud-init/instance-data.json; do [ -r "$f" ] && { echo "== $f"; head -c 4000 "$f"; echo; }; done
  [ -r /var/lib/waagent/ovf-env.xml ] && echo "Azure ovf-env.xml present"
  ls /var/lib/amazon/ssm 2>/dev/null | head -n 5 | sed 's/^/AWS SSM: /'
  echo "note: no metadata service was queried (no network traffic from the examined host)"
  return 0
}
security_agents() {
  : > "$ITEM_OUT/found.txt"
  chk() { [ -e "$2" ] && { echo "$1: $2" >> "$ITEM_OUT/found.txt"; return 0; }; return 1; }
  chk crowdstrike /opt/CrowdStrike && { mk "$ITEM_OUT/crowdstrike"; srv /opt/CrowdStrike/falconctl -g --rfm-state --version --aid --cid --tags > "$ITEM_OUT/crowdstrike/falconctl.txt" 2>&1; }
  chk defender /opt/microsoft/mdatp && { mk "$ITEM_OUT/defender"; for c in health "threat list" "threat quarantine list" "exclusion list"; do srv mdatp $c > "$ITEM_OUT/defender/$(safe "$c").txt" 2>&1; done; cpo "$ITEM_OUT/defender" -R /var/log/microsoft/mdatp /var/opt/microsoft/mdatp/wdavhistory 2>/dev/null; }
  chk sentinelone /opt/sentinelone && { mk "$ITEM_OUT/sentinelone"; srv /opt/sentinelone/bin/sentinelctl management status > "$ITEM_OUT/sentinelone/status.txt" 2>&1; srv /opt/sentinelone/bin/sentinelctl version > "$ITEM_OUT/sentinelone/version.txt" 2>&1; }
  chk sophos /opt/sophos-spl && cpo "$ITEM_OUT/sophos" -R /opt/sophos-spl/base/etc /opt/sophos-spl/logs /opt/sophos-spl/plugins/av/log
  chk trendmicro /opt/ds_agent && cpo "$ITEM_OUT/trendmicro" -R /var/opt/ds_agent/diag /var/log/ds_agent
  chk wazuh-ossec /var/ossec && { srv /var/ossec/bin/wazuh-control status > "$ITEM_OUT/wazuh-status.txt" 2>&1 || srv /var/ossec/bin/ossec-control status > "$ITEM_OUT/wazuh-status.txt" 2>&1; }
  chk osquery /etc/osquery; chk clamav /etc/clamav && has clamconf && srv clamconf > "$ITEM_OUT/clamconf.txt" 2>&1
  chk elastic-agent /opt/Elastic && cpo "$ITEM_OUT/elastic" -R /opt/Elastic/Agent/data/elastic-agent-*/logs
  chk qualys /usr/local/qualys && cpo "$ITEM_OUT/qualys" -R /var/log/qualys
  chk tanium /opt/Tanium; chk rapid7 /opt/rapid7 && cpo "$ITEM_OUT/rapid7" -R /opt/rapid7/ir_agent/components/insight_agent/common/agent.log
  chk monarx /etc/monarx-agent.conf; chk imunify /etc/sysconfig/imunify360; chk aide /var/lib/aide; chk auditbeat /etc/auditbeat; chk falco /etc/falco
  ps -eo pid,user:32,lstart,args -ww | grep -iE 'falcon|mdatp|wdavdaemon|sentinel|sophos|ds_agent|wazuh|ossec|osqueryd|clamd|freshclam|elastic-agent|qualys|tanium|rapid7|ir_agent|monarx|imunify|falco|auditbeat|crowdsec' | grep -v ' grep ' > "$ITEM_OUT/agent-processes.txt"
  rm_empty "$ITEM_OUT"; [ -s "$ITEM_OUT/found.txt" ] || { rm -f "${ITEM_OUT:?}/found.txt"; return 10; }; return 0
}
module_details() {
  printf 'module\tsize\tused_by\tstate\ttaint\tfile\tsha256\tsigner\tsig_key\tversion\tsrcversion\tin_running_kernel_tree\n'
  kv=$(uname -r)
  awk '{print $1"\t"$2"\t"$4"\t"$5}' /proc/modules | while IFS="$TAB" read -r m sz used st; do
    t=$(cat "/sys/module/$m/taint" 2>/dev/null)
    f=$(modinfo -k "$kv" -F filename "$m" 2>/dev/null | head -n 1); [ -n "$f" ] || f=$(srv modinfo -F filename "$m" 2>/dev/null | head -n 1)
    sg=$(srv modinfo -F signer "$m" 2>/dev/null | head -n 1); sk=$(srv modinfo -F sig_key "$m" 2>/dev/null | head -n 1)
    ver=$(cat "/sys/module/$m/version" 2>/dev/null); src=$(cat "/sys/module/$m/srcversion" 2>/dev/null)
    h=""; tree=no; case "$f" in /lib/modules/$kv/*|/usr/lib/modules/$kv/*) tree=yes;; esac
    [ -f "$f" ] && h=$(sha "$f")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$m" "$sz" "$used" "$st" "${t:--}" "${f:--}" "${h:--}" "${sg:--}" "${sk:--}" "${ver:--}" "${src:--}" "$tree"
  done
  return 0
}
hidden_module_check() {
  awk '{print $1}' /proc/modules | sort > "$C0F_TMP/m.proc"
  for d in /sys/module/*; do [ -d "$d/sections" ] || [ -f "$d/initstate" ] && echo "${d##*/}"; done | sort > "$C0F_TMP/m.sys"
  grep -oE '\[[A-Za-z0-9_]+\]$' /proc/kallsyms 2>/dev/null | tr -d '[]' | sort -u > "$C0F_TMP/m.kall"
  echo "== modules with sysfs sections/initstate but missing from /proc/modules (HIDDEN?)"; comm -13 "$C0F_TMP/m.proc" "$C0F_TMP/m.sys"
  echo "== modules owning symbols in /proc/kallsyms but missing from /proc/modules (HIDDEN?)"; comm -13 "$C0F_TMP/m.proc" "$C0F_TMP/m.kall"
  echo "== modules in /proc/modules without a sysfs entry"; comm -23 "$C0F_TMP/m.proc" "$C0F_TMP/m.sys"
  echo "counts: proc=$(wc -l < "$C0F_TMP/m.proc") sysfs=$(wc -l < "$C0F_TMP/m.sys") kallsyms=$(wc -l < "$C0F_TMP/m.kall")"
  echo "kallsyms sha256 (for comparison with a later run): $(sha /proc/kallsyms)"
  return 0
}
ebpf_tracing() {
  if has bpftool; then srv bpftool prog show > "$ITEM_OUT/bpftool-prog.txt" 2>&1; srv bpftool map show > "$ITEM_OUT/bpftool-map.txt" 2>&1; srv bpftool link show > "$ITEM_OUT/bpftool-link.txt" 2>&1; srv bpftool net show > "$ITEM_OUT/bpftool-net.txt" 2>&1; srv bpftool perf show > "$ITEM_OUT/bpftool-perf.txt" 2>&1; fi
  for p in /proc/[0-9]*; do for fd in "$p"/fd/*; do l=$(readlink "$fd" 2>/dev/null); case "$l" in anon_inode:bpf-prog|anon_inode:bpf-map|anon_inode:bpf_link|anon_inode:bpf-link) echo "pid ${p##*/} $(cat "$p/comm" 2>/dev/null) fd ${fd##*/} $l $(tr '\n' ' ' 2>/dev/null < "$p/fdinfo/${fd##*/}")";; esac; done; done > "$ITEM_OUT/bpf-fds-per-process.txt"
  [ -d /sys/fs/bpf ] && find /sys/fs/bpf -maxdepth 4 -printf '%p\t%y\t%TY-%Tm-%Td %TT\n' > "$ITEM_OUT/bpffs-pins.txt" 2>/dev/null
  for t in /sys/kernel/tracing /sys/kernel/debug/tracing; do [ -d "$t" ] || continue
    for f in kprobe_events uprobe_events enabled_functions set_ftrace_filter current_tracer trace_options dynamic_events set_event; do [ -r "$t/$f" ] && { echo "== $t/$f"; head -n 2000 "$t/$f"; }; done > "$ITEM_OUT/tracing-state.txt" 2>&1; break; done
  cat /proc/sys/kernel/ftrace_enabled > "$ITEM_OUT/ftrace_enabled.txt" 2>/dev/null
  rm_empty "$ITEM_OUT"; return 0
}
cross_check_processes() {
  pids | sort > "$C0F_TMP/p.readdir"
  ps -e -o pid= | tr -d ' ' | sort > "$C0F_TMP/p.kitps"
  has ps && srv ps -e -o pid= 2>/dev/null | tr -d ' ' | sort > "$C0F_TMP/p.srvps"
  max=$(sort -n "$C0F_TMP/p.readdir" | tail -n 1); max=$((max + 2000)); pm=$(cat /proc/sys/kernel/pid_max); [ "$max" -gt "$pm" ] && max=$pm
  i=1; : > "$C0F_TMP/p.brute"; while [ $i -le $max ]; do [ -e "/proc/$i/status" ] && echo $i; i=$((i+1)); done > "$C0F_TMP/p.brute"
  sort "$C0F_TMP/p.brute" -o "$C0F_TMP/p.brute"
  echo "PIDs reachable by /proc/<pid> (brute force 1..$max) but NOT listed by readdir(/proc) - hidden processes (threads excluded):"
  comm -23 "$C0F_TMP/p.brute" "$C0F_TMP/p.readdir" | while read -r p; do tg=$(awk '/^Tgid:/{print $2}' "/proc/$p/status" 2>/dev/null); [ "$tg" = "$p" ] && echo "  HIDDEN? pid $p $(cat "/proc/$p/comm" 2>/dev/null) $(tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline" 2>/dev/null)"; done
  echo "listed by readdir but not seen by kit ps (short-lived processes appear here too):"; comm -23 "$C0F_TMP/p.readdir" "$C0F_TMP/p.kitps" | head -n 50 | sed 's/^/  /'
  if [ -s "$C0F_TMP/p.srvps" ]; then echo "seen by kit ps but NOT by the server's ps (possible tampered ps):"; comm -23 "$C0F_TMP/p.kitps" "$C0F_TMP/p.srvps" | while read -r p; do [ -d "/proc/$p" ] && echo "  pid $p $(cat "/proc/$p/comm" 2>/dev/null)"; done
  else echo "server ps not available: comparison skipped"; fi
  return 0
}
cross_check_network() {
  for f in /proc/net/tcp /proc/net/tcp6; do awk 'NR>1 && $4=="0A"{split($2,a,":"); print a[2]}' "$f"; done 2>/dev/null | while read -r h; do printf '%d\n' "0x$h"; done | sort -u > "$C0F_TMP/n.proc"
  ss -Htln 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -u > "$C0F_TMP/n.kitss"
  netstat -tln 2>/dev/null | awk 'NR>2{n=split($4,a,":"); print a[n]}' | sort -u > "$C0F_TMP/n.kitnetstat"
  { has ss && srv ss -Htln 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}'; } | sort -u > "$C0F_TMP/n.srvss"
  { has netstat && srv netstat -tln 2>/dev/null | awk 'NR>2{n=split($4,a,":"); print a[n]}'; } | sort -u > "$C0F_TMP/n.srvnetstat"
  echo "TCP listening ports from /proc/net: $(tr '\n' ' ' < "$C0F_TMP/n.proc")"
  echo "in /proc/net but missing from kit ss : $(comm -23 "$C0F_TMP/n.proc" "$C0F_TMP/n.kitss" | tr '\n' ' ')"
  echo "in /proc/net but missing from kit netstat: $(comm -23 "$C0F_TMP/n.proc" "$C0F_TMP/n.kitnetstat" | tr '\n' ' ')"
  [ -s "$C0F_TMP/n.srvss" ] && echo "in /proc/net but missing from SERVER ss: $(comm -23 "$C0F_TMP/n.proc" "$C0F_TMP/n.srvss" | tr '\n' ' ')" || echo "server ss not available"
  [ -s "$C0F_TMP/n.srvnetstat" ] && echo "in /proc/net but missing from SERVER netstat: $(comm -23 "$C0F_TMP/n.proc" "$C0F_TMP/n.srvnetstat" | tr '\n' ' ')" || echo "server netstat not available"
  return 0
}
cross_check_files() {
  for d in /etc /usr/bin /usr/sbin /bin /sbin /tmp /var/tmp /dev/shm /lib/modules /root; do [ -d "$d" ] || continue; [ -L "$d" ] && continue
    ls -a "$d" 2>/dev/null | sort > "$C0F_TMP/f.kitls"; find "$d" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort > "$C0F_TMP/f.find"
    busybox ls -a "$d" 2>/dev/null | sort > "$C0F_TMP/f.bb"
    { has ls && srv ls -a "$d" 2>/dev/null; } | sort > "$C0F_TMP/f.srv"
    a=$(comm -3 "$C0F_TMP/f.kitls" "$C0F_TMP/f.find" | grep -vxE '\s*\.{1,2}' | tr '\n' ' '); b=$(comm -3 "$C0F_TMP/f.kitls" "$C0F_TMP/f.bb" | tr '\n' ' ')
    c="(server ls not available)"; [ -s "$C0F_TMP/f.srv" ] && c=$(comm -23 "$C0F_TMP/f.kitls" "$C0F_TMP/f.srv" | tr '\n' ' ')
    echo "$d: kit-ls-vs-find=[${a}] kit-ls-vs-busybox=[${b}] hidden-from-server-ls=[${c}]"
  done
  return 0
}
run_chkrootkit() {
  cd "$BIN/chkrootkit" 2>/dev/null || { echo "kit chkrootkit folder missing"; return 11; }
  # chkrootkit calls awk, egrep, strings, ps, netstat, ... from PATH: kit tools only
  PATH="$BIN/chkrootkit:$BIN:$C0F_TMP/applets" ./chkrootkit -x > "$ITEM_OUT/chkrootkit-expert.txt" 2>&1
  PATH="$BIN/chkrootkit:$BIN:$C0F_TMP/applets" ./chkrootkit > "$ITEM_OUT/chkrootkit.txt" 2>&1; rc=$?
  { echo "INFECTED / suspicious lines (require analyst review, false positives are common):"; grep -E 'INFECTED|Vulnerable|suspicious|Warning|PACKET SNIFFER|deleted' "$ITEM_OUT/chkrootkit.txt"; } > "$ITEM_OUT/summary.txt"
  return 0
}
kernel_logs_now() { dmesg -T 2>/dev/null || dmesg 2>&1; echo; echo "== dmesg with raw timestamps"; dmesg -x 2>&1 | tail -n 5000; return 0; }
