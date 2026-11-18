# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# c0f-lib.sh - functions used by c0f.sh and by catalog items (each item runs in its own
# "busybox sh -c '. c0f-lib.sh; <command>'" process with a time limit).
# Conventions for FUNC/DERIVED items: write into $ITEM_OUT (folder or file), return
#   0 OK | 10 EMPTY | 11 NOT_FOUND | 12 NOT_APPLICABLE | 13 PARTIAL | 14 DENIED | 15 UNSUPPORTED_ARCH | 16 NO_SPACE
# Sub-results (one line per sub-artefact) go to $C0F_SUB via: sub STATUS REASON DETAIL

[ -n "$C0F_BLOCKED_SH" ] && [ -f "$C0F_BLOCKED_SH" ] && . "$C0F_BLOCKED_SH"
SRV_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
TAB=$(printf '\t')

# ---- server programs (UNTRUSTED_TOOL) --------------------------------------------------------------
srv_path() {
  case "$1" in /*) [ -x "$1" ] && [ ! -d "$1" ] && { echo "$1"; return 0; }; return 1;; esac
  _o=$IFS; IFS=:
  for _d in $SRV_PATH; do
    if [ -x "$_d/$1" ] && [ ! -d "$_d/$1" ]; then
      case "$_d/$1" in "$KIT"/*) continue;; esac
      IFS=$_o; echo "$_d/$1"; return 0
    fi
  done
  IFS=$_o; return 1
}
srv() {
  _n=$1; shift
  _p=$(srv_path "$_n") || { echo "C0F: server command not found: $_n" >&2; return 127; }
  [ -n "$ITEM_SRVLOG" ] && echo "$_p" >> "$ITEM_SRVLOG"
  PATH=$SRV_PATH "$_p" "$@"; _srv_rc=$?
  # a server program killed by SIGILL/SIGTRAP/SIGABRT/SIGBUS/SIGFPE/SIGSEGV/SIGSYS is recorded (SIGPIPE from "| head" is not)
  case $_srv_rc in 132|133|134|135|136|139|159) [ -n "$ITEM_SRVLOG" ] && printf '%s\t%s\n' "$_p" "$_srv_rc" >> "$ITEM_SRVLOG.crash";; esac
  return $_srv_rc
}
has() { srv_path "$1" >/dev/null 2>&1; }
is_systemd() { [ -d /run/systemd/system ]; }
fam() { case " $OS_FAMILY $OS_LIKE $OS_ID " in *" $1 "*) return 0;; esac; return 1; }
sub() { [ -n "$C0F_SUB" ] && printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\n' '  ')" >> "$C0F_SUB"; }
note() { printf '%s\n' "$*"; }
# remove zero-size files directly inside folder $1 (never recursive, refuses an empty argument)
rm_empty() { _red=${1:?rm_empty needs a folder}; for _ref in "$_red"/*; do [ -f "$_ref" ] && [ ! -s "$_ref" ] && rm -f -- "${_ref:?}"; done; return 0; }
mk() { mkdir -p "$@" 2>/dev/null; }

# ---- copying -------------------------------------------------------------------------------------
c0f_copy() { c0f-copy -M "$ITEM_META" -o "$ITEM_FILES" -e "$C0F_EXCL" -e "$C0F_KITDIR" "$@"; }
# cpo DESTROOT [c0f-copy options] PATH...   (absolute paths are recreated under DESTROOT)
cpo() { _d=$1; shift; mk "$_d"; c0f-copy -M "$ITEM_META" -o "$_d" -e "$C0F_EXCL" -e "$C0F_KITDIR" "$@" 2>>"$C0F_TMP/copy-stderr.log"; }
# copied_any META_BEFORE_LINES -> true when rows with OK/EMPTY/CHANGED were added after line N
meta_lines() { [ -f "$ITEM_META" ] && wc -l < "$ITEM_META" || echo 0; }
copied_since() { [ -f "$ITEM_META" ] || return 1; awk -F'\t' -v n="$1" 'NR>n && ($1=="OK"||$1=="CHANGED_DURING_COPY"||$1=="EMPTY"){f=1} END{exit !f}' "$ITEM_META"; }

# ---- users / homes -----------------------------------------------------------------------------------
# each_home: "user<TAB>uid<TAB>home<TAB>shell" for every passwd entry whose home is an existing folder (root first, homes de-duplicated)
each_home() {
  awk -F: '{print $1"\t"$3"\t"$6"\t"$7}' /etc/passwd 2>/dev/null | while IFS="$TAB" read -r u id h s; do
    case "$h" in ""|/|/nonexistent|/dev/null|/var/empty|/proc|/sys|/bin|/sbin|/usr/sbin|/usr/bin) continue;; esac
    [ -d "$h" ] && printf '%s\t%s\t%s\t%s\n' "$u" "$id" "$h" "$s"
  done | awk -F'\t' '!seen[$3]++'
  for h in /home/*; do [ -d "$h" ] && ! awk -F: -v h="$h" '$6==h{f=1} END{exit !f}' /etc/passwd 2>/dev/null && printf '%s\t%s\t%s\t%s\n' "(no-passwd-entry)${h##*/}" "?" "$h" "-"; done
}
pids() { for _p in /proc/[0-9]*; do echo "${_p##*/}"; done | sort -n; }
sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._@+-' '_' | cut -c1-120; }
lstat_row() { stat -c '%n%t%s%t%A%t%U%t%G%t%y%t%z%t%w' "$1" 2>/dev/null | sed "s/%t/$TAB/g"; }

# ---- OS detection and profile ---------------------------------------------------------------------
os_detect() {
  OS_ID=""; OS_NAME=""; OS_VERSION_ID=""; OS_LIKE=""
  for f in /etc/os-release /usr/lib/os-release; do
    [ -r "$f" ] || continue
    while IFS='=' read -r k v; do
      v=${v#\"}; v=${v%\"}; v=${v#\'}; v=${v%\'}
      case "$k" in ID) OS_ID=$v;; ID_LIKE) OS_LIKE=$v;; VERSION_ID) OS_VERSION_ID=$v;; PRETTY_NAME) OS_NAME=$v;; esac
    done < "$f"; break
  done
  if [ -z "$OS_ID" ]; then
    if [ -r /etc/redhat-release ]; then OS_NAME=$(cat /etc/redhat-release); OS_VERSION_ID=$(sed -n 's/.*release \([0-9][0-9.]*\).*/\1/p' /etc/redhat-release)
      case "$OS_NAME" in CentOS*) OS_ID=centos;; Red*) OS_ID=rhel;; Fedora*) OS_ID=fedora;; *) OS_ID=rhel;; esac; OS_LIKE="rhel fedora"
    elif [ -r /etc/debian_version ]; then OS_ID=debian; OS_VERSION_ID=$(cut -d. -f1 /etc/debian_version); OS_NAME="Debian $(cat /etc/debian_version)"
    elif [ -r /etc/alpine-release ]; then OS_ID=alpine; OS_VERSION_ID=$(cat /etc/alpine-release); OS_NAME="Alpine $OS_VERSION_ID"
    elif [ -r /etc/arch-release ]; then OS_ID=arch; OS_NAME="Arch Linux"
    elif [ -r /etc/SuSE-release ]; then OS_ID=suse; OS_NAME=$(head -n 1 /etc/SuSE-release); OS_LIKE=suse
    elif [ -r /etc/gentoo-release ]; then OS_ID=gentoo; OS_NAME=$(cat /etc/gentoo-release)
    else OS_ID=unknown; OS_NAME="unknown Linux"; fi
  fi
  [ -n "$OS_NAME" ] || OS_NAME="$OS_ID $OS_VERSION_ID"
  # profile: first row of os-profile.tsv whose id regex matches ID or an ID_LIKE word and version is in range
  _row=$(awk -F'\t' -v id="$OS_ID" -v like="$OS_LIKE" -v ver="$OS_VERSION_ID" '
    function vnum(s,  a,n){ n=split(s,a,"."); return (a[1]+0)*1000 + (n>1 ? a[2]+0 : 0) }
    function vok(  v){ if (ver=="") return ($3=="-" && $4=="-"); v=vnum(ver); if ($3!="-" && v < vnum($3)) return 0; if ($4!="-" && v > vnum($4)) return 0; return 1 }
    NR==1 || /^#/ {next}
    { L[NR]=$0 }
    { if (!p1 && id ~ ("^(" $2 ")$") && $1!="generic" && vok()) p1=$0
      n=split(like,W," "); for(i=1;i<=n;i++) if (!p2 && W[i] ~ ("^(" $2 ")$") && $1!="generic" && vok()) p2=$0 }
    END{ if (p1) print p1; else if (p2) print p2 }' "$KIT/os-profile.tsv" 2>/dev/null)
  [ -n "$_row" ] || _row=$(awk -F'\t' '$1=="generic"{print; exit}' "$KIT/os-profile.tsv" 2>/dev/null)
  OS_PROFILE=$(printf '%s' "$_row" | cut -f1); OS_FAMILY=$(printf '%s' "$_row" | cut -f5); OS_PKG=$(printf '%s' "$_row" | cut -f6)
  OS_INIT=$(printf '%s' "$_row" | cut -f7); OS_EXPECT_MUST=$(printf '%s' "$_row" | cut -f8); OS_EXPECT_DEFAULT=$(printf '%s' "$_row" | cut -f9)
  OS_PROFILE_NOTE=$(printf '%s' "$_row" | cut -f10)
  [ -n "$OS_PROFILE" ] || { OS_PROFILE=none; OS_FAMILY=unknown; }
  # dynamic expectations: with systemd as PID 1, systemctl and journalctl must exist
  [ -d /run/systemd/system ] && OS_EXPECT_MUST="$OS_EXPECT_MUST systemctl journalctl"
  OS_EXPECT_MUST=$(echo $OS_EXPECT_MUST | tr ' ' '\n' | grep -v '^-$' | sort -u | tr '\n' ' ')
  OS_EXPECT_DEFAULT=$(echo $OS_EXPECT_DEFAULT | tr ' ' '\n' | grep -v '^-$' | sort -u | tr '\n' ' ')
  # running inside a container: drop init expectations
  if grep -qaE 'docker|containerd|kubepods|lxc|libpod' /proc/1/cgroup 2>/dev/null || [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
    C0F_IN_CONTAINER=yes; OS_EXPECT_MUST=$(echo $OS_EXPECT_MUST | tr ' ' '\n' | grep -vE '^(systemctl|journalctl|loginctl|timedatectl)$' | tr '\n' ' ')
  else C0F_IN_CONTAINER=no; fi
  export C0F_IN_CONTAINER OS_PROFILE_NOTE
}

# ---- output location helpers ----------------------------------------------------------------------
out_is_external() {
  OUT_EXTERNAL=NO; OUT_DEVICE=""
  case "$(stat -f -c %T "$OUTDIR" 2>/dev/null)" in nfs*|cifs|smb*|fuse.sshfs|9p|ceph) OUT_EXTERNAL=YES; OUT_DEVICE=network; return;; esac
  _mm=$(stat -c '%Hd:%Ld' "$OUTDIR" 2>/dev/null)
  [ -n "$_mm" ] || return
  _sys=$(readlink -f "/sys/dev/block/$_mm" 2>/dev/null)
  OUT_DEVICE=${_sys##*/}
  case "$_sys" in */usb*|*/mmc*) OUT_EXTERNAL=YES; return;; esac
  for _r in "$_sys/removable" "$_sys/../removable"; do [ -f "$_r" ] && [ "$(cat "$_r")" = 1 ] && { OUT_EXTERNAL=YES; return; }; done
}
estimate_kb() {
  _t=0
  for d in /var/log /etc /var/lib/docker/containers /var/log/pods /var/lib/mysql /var/lib/pgsql /var/lib/postgresql /var/www /var/spool /var/cache/apt /var/cache/dnf /var/cache/yum; do
    [ -d "$d" ] || continue
    _k=$(timeout 60 du -skx "$d" 2>/dev/null | cut -f1); _t=$((_t + ${_k:-0}))
  done
  [ "$C0F_OPT_RAM" = 1 ] && [ "$ARCH" != armv7 ] && _t=$((_t + $(awk '/^MemTotal/{print $2}' /proc/meminfo)))
  [ "$C0F_OPT_SWAP" = 1 ] && _t=$((_t + $(awk 'NR>1{s+=$4} END{print s+0}' /proc/swaps)))
  [ "$C0F_OPT_TIMELINE" = 1 ] && _t=$((_t + $(df -Pi 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev\//{s+=$3} END{printf "%d", s*0.25}')))
  echo "$_t"
}
pcap_cleanup() { [ -f "$C0F_TMP/run/pcap.pid" ] && { kill "$(cat "$C0F_TMP/run/pcap.pid")" 2>/dev/null; rm -f "${C0F_TMP:?}/run/pcap.pid"; }; }
is_k8s_node() { [ -d /etc/kubernetes ] || [ -d /var/lib/kubelet ] || [ -d /var/lib/rancher ] || [ -d /var/snap/microk8s ] || has kubelet || has k3s; }
k8s_kubeconfig_available() {
  [ -n "$C0F_KUBECONFIG" ] && [ -r "$C0F_KUBECONFIG" ] && return 0
  for f in /etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/snap/microk8s/current/credentials/client.config /root/.kube/config; do [ -r "$f" ] && return 0; done
  return 1
}
