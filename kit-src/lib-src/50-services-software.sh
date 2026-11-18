# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D09 / D10 =======================
# ---- package file index (path<TAB>package), built once per run, shared by several items ----------
pkg_index() {
  idx="$C0F_TMP/pkgfiles.idx"; [ -f "$idx" ] && return 0; : > "$idx.tmp"
  if [ -d /var/lib/dpkg/info ]; then
    for f in /var/lib/dpkg/info/*.list; do p=${f##*/}; p=${p%.list}; awk -v p="$p" '{print $0"\t"p}' "$f"; done >> "$idx.tmp" 2>/dev/null
  fi
  if has rpm; then rpm_db_copy && srv rpm --dbpath "$C0F_TMP/rpmdb" -qa --qf '[%{FILENAMES}\t%{NAME}\n]' >> "$idx.tmp" 2>/dev/null; fi
  if [ -f /lib/apk/db/installed ]; then
    awk '/^P:/{p=substr($0,3)} /^F:/{d=substr($0,3)} /^R:/{print "/"d"/"substr($0,3)"\t"p}' /lib/apk/db/installed >> "$idx.tmp"
  fi
  if [ -d /var/lib/pacman/local ]; then
    for d in /var/lib/pacman/local/*/; do p=$(sed -n '/^%NAME%/{n;p;q}' "$d/desc" 2>/dev/null); awk -v p="$p" '/^%FILES%/{f=1;next} /^%/{f=0} f && NF{print "/"$0"\t"p}' "$d/files" 2>/dev/null; done >> "$idx.tmp"
  fi
  sort -u "$idx.tmp" > "$idx"; rm -f "${idx:?}.tmp"
  # keyed copy: every line starts with \001 so a lookup "\001PATH<TAB>" matches the whole path, never a suffix of a longer one
  sed "s/^/$(printf '\001')/" "$idx" > "$idx.k"
}
# pkg_owner PATH -> package name or empty (handles /usr-merge and symlinked paths)
pkg_owner() {
  pkg_index; _p=$1; _r=$(readlink -f "$_p" 2>/dev/null)
  for _c in "$_p" "$_r" "/usr$_p" "${_p#/usr}" "/usr$_r" "${_r#/usr}"; do
    [ -n "$_c" ] || continue
    _o=$(grep -F -m1 "$(printf '\001')$_c$TAB" "$C0F_TMP/pkgfiles.idx.k" | cut -f2); [ -n "$_o" ] && { echo "$_o"; return 0; }
  done
  return 1
}
rpm_db_copy() {
  [ -d "$C0F_TMP/rpmdb" ] && return 0
  for d in /var/lib/rpm /usr/lib/sysimage/rpm; do
    [ -d "$d" ] && [ -n "$(ls "$d" 2>/dev/null)" ] && { mk "$C0F_TMP/rpmdb"; cp -a "$d"/. "$C0F_TMP/rpmdb/" 2>/dev/null; return 0; }
  done
  return 1
}
# sqlite_dump DB OUTDIR : copy the database (+wal/shm) and export every table as TSV (read-only, from the copy)
sqlite_dump() {
  _db=$1; _o=$2; mk "$_o"; _c="$C0F_TMP/sqlcopy_$$"; mk "$_c"
  cp "$_db" "$_c/db" 2>/dev/null || return 1
  for s in -wal -shm -journal; do [ -f "$_db$s" ] && cp "$_db$s" "$_c/db$s"; done
  sqlite3 -readonly "$_c/db" ".tables" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | while read -r t; do
    sqlite3 -readonly -header -separator "$TAB" "$_c/db" "SELECT * FROM \"$t\";" > "$_o/$(safe "$t").tsv" 2>&1
  done
  sqlite3 -readonly "$_c/db" ".schema" > "$_o/schema.sql" 2>&1
  rm -rf "${_c:?}"; return 0
}

systemd_service_details() {
  srv systemctl list-units --all --type=service --no-legend --plain --full 2>/dev/null | awk '{print $1}' > "$C0F_TMP/svc.list"
  srv systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' >> "$C0F_TMP/svc.list"
  sort -u "$C0F_TMP/svc.list" | grep '\.service$' | while read -r u; do
    case "$u" in *@.service) continue;; esac
    srv systemctl show --no-pager "$u" > "$ITEM_OUT/$(safe "$u").show.txt" 2>&1
    srv systemctl cat --no-pager "$u" > "$ITEM_OUT/$(safe "$u").cat.txt" 2>&1
  done
  return 0
}
services_table() {
  q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"; }
  echo "unit,manager,load,active,sub,unit_file_state,main_pid,active_since,user,exec_start,binary,binary_sha256,binary_package,unit_file,unit_file_mtime,unit_file_ctime,unit_file_btime,enabled_link,enabled_link_time,unit_file_package,dropins,origin"
  d="$C0F_OUT/09_services/services-detail"
  if [ -d "$d" ] && ls "$d"/*.show.txt >/dev/null 2>&1; then
    for s in "$d"/*.show.txt; do
      g() { sed -n "s/^$1=//p" "$s" | head -n 1; }
      u=$(g Id); fp=$(g FragmentPath); es=$(g ExecStart); bin=$(printf '%s' "$es" | sed -n 's/.*path=\([^ ;]*\).*/\1/p')
      pid=$(g MainPID); [ "$pid" = 0 ] && pid=""; [ -n "$pid" ] && [ -e "/proc/$pid/exe" ] && bin=$(readlink "/proc/$pid/exe")
      bh=""; bp=""; [ -n "$bin" ] && [ -f "${bin% (deleted)}" ] && { bh=$(sha "${bin% (deleted)}"); bp=$(pkg_owner "$bin"); }
      fm=""; fc=""; fb=""; fpk=""; [ -n "$fp" ] && [ -f "$fp" ] && { fm=$(stat -c %y "$fp"); fc=$(stat -c %z "$fp"); fb=$(stat -c %w "$fp"); fpk=$(pkg_owner "$fp"); }
      el=$(ls -d /etc/systemd/system/*.wants/"$u" 2>/dev/null | head -n 1); elt=""; [ -n "$el" ] && elt=$(stat -c %z "$el")
      orig=package; [ -z "$fpk" ] && orig="NO PACKAGE (created by hand or by an installer)"; case "$fp" in /run/systemd/transient/*) orig="TRANSIENT (systemd-run)";; esac
      echo "$(q "$u"),systemd,$(g LoadState),$(g ActiveState),$(g SubState),$(g UnitFileState),$pid,$(q "$(g ActiveEnterTimestamp)"),$(q "$(g User)"),$(q "$es"),$(q "$bin"),$bh,$(q "$bp"),$(q "$fp"),$fm,$fc,$fb,$(q "$el"),$elt,$(q "$fpk"),$(q "$(g DropInPaths)"),$(q "$orig")"
    done
  fi
  for s in /etc/init.d/*; do [ -f "$s" ] || continue
    n=${s##*/}; case "$n" in README|skeleton|functions|rc|rcS|halt|reboot|single) continue;; esac
    lk=$(ls -d /etc/rc[2-5].d/S*"$n" 2>/dev/null | head -n 1); pk=$(pkg_owner "$s"); o=package; [ -z "$pk" ] && o="NO PACKAGE"
    echo "$(q "$n"),sysv/openrc,,,,$( [ -n "$lk" ] && echo enabled || echo -),,,,$(q "$s"),,$(sha "$s"),,$(q "$s"),$(stat -c %y "$s"),$(stat -c %z "$s"),$(stat -c %w "$s"),$(q "$lk"),$( [ -n "$lk" ] && stat -c %z "$lk"),$(q "$pk"),,$(q "$o")"
  done
  return 0
}
listeners_without_service() {
  printf 'proto\tlocal\tpid\tprocess\texe\tcgroup\tclassification\n'
  ss -Htulpn 2>/dev/null | while read -r proto st rq sq local peer procs; do
    pid=$(printf '%s' "$procs" | sed -n 's/.*pid=\([0-9]*\).*/\1/p'); [ -n "$pid" ] || { printf '%s\t%s\t-\t-\t-\t-\tNO_PROCESS (kernel or hidden)\n' "$proto" "$local"; continue; }
    cg=$(tail -n 1 "/proc/$pid/cgroup" 2>/dev/null); exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    case "$cg" in *.service*) c=service;; *docker*|*containerd*|*kubepods*|*libpod*|*lxc*) c=container;; *session-*.scope*|*user@*) c="STARTED FROM A USER SESSION";; *) c="NOT IN A SERVICE";; esac
    is_c0f_pid "$pid" && c="C0F (this collector)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$proto" "$local" "$pid" "$(cat "/proc/$pid/comm" 2>/dev/null)" "$exe" "$cg" "$c"
  done
  return 0
}
packages_list() {
  n=0
  if [ -f /var/lib/dpkg/status ]; then n=1
    { printf 'package\tversion\tarch\tstatus\tinstall_time_utc(list file mtime)\tmaintainer\n'
      awk 'BEGIN{RS=""; FS="\n"} {p=v=a=s=m=""; for(i=1;i<=NF;i++){ if($i~/^Package: /)p=substr($i,10); else if($i~/^Version: /)v=substr($i,10); else if($i~/^Architecture: /)a=substr($i,15); else if($i~/^Status: /)s=substr($i,9); else if($i~/^Maintainer: /)m=substr($i,13)} if(p!="") print p"\t"v"\t"a"\t"s"\t"m}' /var/lib/dpkg/status |
      while IFS="$TAB" read -r p v a s m; do l=/var/lib/dpkg/info/$p.list; [ -f "$l" ] || l=/var/lib/dpkg/info/$p:$a.list
        t=$( [ -f "$l" ] && date -u -r "$l" +%FT%TZ ); printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$v" "$a" "$s" "$t" "$m"; done; } > "$ITEM_OUT/dpkg-installed.tsv"
    awk -F'\t' 'NR>1 && $4 ~ /deinstall|config-files/' "$ITEM_OUT/dpkg-installed.tsv" > "$ITEM_OUT/dpkg-removed-config-left.tsv"
    has apt && srv apt list --installed > "$ITEM_OUT/apt-list-installed.txt" 2>/dev/null
  fi
  if has rpm; then n=1; rpm_db_copy
    srv rpm --dbpath "$C0F_TMP/rpmdb" -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME:date}\t%{INSTALLTIME}\t%{BUILDTIME:date}\t%{VENDOR}\t%{PACKAGER}\t%{BUILDHOST}\t%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\n' 2>&1 | { printf 'name\tversion\tarch\tinstall_time\tinstall_epoch\tbuild_time\tvendor\tpackager\tbuildhost\tsigpgp\trsaheader\n'; sort; } > "$ITEM_OUT/rpm-installed.tsv"
    { has dnf && srv dnf -C -q repoquery --installed --qf '%{name}\t%{evr}\t%{arch}\t%{from_repo}\n' 2>/dev/null; } > "$ITEM_OUT/rpm-from-repo.tsv"
    [ -s "$ITEM_OUT/rpm-from-repo.tsv" ] || { has yum && srv yum -C -q list installed > "$ITEM_OUT/yum-list-installed.txt" 2>/dev/null; }
  fi
  if [ -f /lib/apk/db/installed ]; then n=1
    { printf 'package\tversion\tarch\tbuild_time_utc\torigin\tmaintainer\n'
      awk '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^A:/{a=substr($0,3)} /^t:/{t=substr($0,3)} /^o:/{o=substr($0,3)} /^m:/{m=substr($0,3)} /^$/{if(p!="")print p"\t"v"\t"a"\t"t"\t"o"\t"m; p=""} END{if(p!="")print p"\t"v"\t"a"\t"t"\t"o"\t"m}' /lib/apk/db/installed; } > "$ITEM_OUT/apk-installed.tsv"
    cp /etc/apk/world "$ITEM_OUT/apk-world.txt" 2>/dev/null
  fi
  if [ -d /var/lib/pacman/local ]; then n=1
    { printf 'package\tversion\tarch\tinstall_date\tpackager\treason\n'
      for d in /var/lib/pacman/local/*/; do awk '/^%NAME%/{getline;n=$0} /^%VERSION%/{getline;v=$0} /^%ARCH%/{getline;a=$0} /^%INSTALLDATE%/{getline;i=$0} /^%PACKAGER%/{getline;p=$0} /^%REASON%/{getline;r=$0} END{print n"\t"v"\t"a"\t"i"\t"p"\t"r}' "$d/desc"; done; } > "$ITEM_OUT/pacman-installed.tsv"
    has pacman && srv pacman -Qm > "$ITEM_OUT/pacman-foreign-aur-local.txt" 2>&1
  fi
  has xbps-query && { n=1; srv xbps-query -l > "$ITEM_OUT/xbps-installed.txt" 2>&1; }
  [ -d /var/db/pkg ] && { n=1; ls -d /var/db/pkg/*/* > "$ITEM_OUT/portage-installed.txt" 2>/dev/null; }
  has nix-env && { n=1; srv nix-env -q > "$ITEM_OUT/nix-user-env.txt" 2>&1; srv nix-store -q --requisites /run/current-system > "$ITEM_OUT/nix-system.txt" 2>&1; }
  has opkg && { n=1; srv opkg list-installed > "$ITEM_OUT/opkg-installed.txt" 2>&1; }
  rm_empty "$ITEM_OUT"
  [ $n = 0 ] && return 12; return 0
}
software_table() {
  q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"; }
  P="$C0F_OUT/10_software/packages"
  echo "name,version,arch,manager,install_time_utc,how_installed,source,installed_by_or_command"
  # apt history: last Requested-By / Commandline per package
  for f in /var/log/apt/history.log*; do [ -f "$f" ] && case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; done 2>/dev/null |
    awk '/^Start-Date:/{d=substr($0,13)} /^Commandline:/{c=substr($0,14)} /^Requested-By:/{r=substr($0,15)} /^(Install|Upgrade|Reinstall):/{n=split(substr($0,index($0,":")+2),a,"), "); for(i=1;i<=n;i++){split(a[i],b,":"); print b[1]"\t"d"\t"r"\t"c}; r=""}' > "$C0F_TMP/apt-by.tsv"
  if [ -f "$P/dpkg-installed.tsv" ]; then
    awk -F'\t' 'NR>1 && $4 ~ / installed$/' "$P/dpkg-installed.tsv" | while IFS="$TAB" read -r p v a s t m; do
      src=$(grep -m1 "^$p/" "$P/apt-list-installed.txt" 2>/dev/null | cut -d' ' -f1 | cut -d/ -f2)
      how=repository; case "$src" in now|*",now"*|'') how="LOCAL FILE or no longer in any repo";; esac
      by=$(awk -F'\t' -v p="$p" '$1==p{l=$3" ("$2") "$4} END{print l}' "$C0F_TMP/apt-by.tsv")
      echo "$(q "$p"),$(q "$v"),$a,dpkg,$t,$(q "$how"),$(q "$src"),$(q "$by")"
    done
  fi
  if [ -f "$P/rpm-installed.tsv" ]; then
    awk -F'\t' 'NR>1' "$P/rpm-installed.tsv" | while IFS="$TAB" read -r n v a it ie bt ven pkr bh sg rs; do
      [ "$n" = gpg-pubkey ] && continue
      repo=$(awk -F'\t' -v n="$n" '$1==n{print $4; exit}' "$P/rpm-from-repo.tsv" 2>/dev/null)
      how=repository; case "$repo" in @commandline|'') how="LOCAL FILE (rpm -i / dnf install ./file) or unknown";; esac
      case "$sg$rs" in *'(none)'*'(none)'*) how="$how; UNSIGNED";; esac
      ts=$(date -u -d "@$ie" +%FT%TZ 2>/dev/null)
      echo "$(q "$n"),$(q "$v"),$a,rpm,$ts,$(q "$how"),$(q "${repo:-$ven}"),"
    done
  fi
  [ -f "$P/apk-installed.tsv" ] && awk -F'\t' 'NR>1{printf "\"%s\",\"%s\",%s,apk,(apk keeps no install time),repository or local,\"%s\",\n",$1,$2,$3,$5}' "$P/apk-installed.tsv"
  [ -f "$P/pacman-installed.tsv" ] && awk -F'\t' 'NR>1{printf "\"%s\",\"%s\",%s,pacman,%s,repository,\"%s\",\n",$1,$2,$3,$4,$5}' "$P/pacman-installed.tsv"
  L="$C0F_OUT/10_software/language-packages"
  [ -f "$L/python-dist-info.tsv" ] && awk -F'\t' 'NR>1{printf "\"%s\",\"%s\",,pip,%s,\"%s\",\"%s\",\n",$1,$2,$5,$3,$4}' "$L/python-dist-info.tsv"
  [ -f "$L/npm-global.tsv" ] && awk -F'\t' 'NR>1{printf "\"%s\",\"%s\",,npm-global,%s,npm,\"%s\",\n",$1,$2,$4,$3}' "$L/npm-global.tsv"
  [ -f "$L/snap-list.txt" ] && awk 'NR>1{printf "\"%s\",\"%s\",,snap,,snap store,\"%s\",\n",$1,$2,$5}' "$L/snap-list.txt"
  return 0
}
pkg_history() {
  n=0
  for db in /var/lib/dnf/history.sqlite /var/lib/dnf/history.sqlite-* /usr/lib/sysimage/libdnf5/transaction_history.sqlite /usr/lib/sysimage/dnf/transaction_history.sqlite /var/lib/yum/history/history-*.sqlite; do
    [ -f "$db" ] || continue; n=1; o="$ITEM_OUT/db_$(safe "${db#/}")"; sqlite_dump "$db" "$o"
    c="$C0F_TMP/hcopy.db"; cp "$db" "$c"; for s in -wal -shm; do [ -f "$db$s" ] && cp "$db$s" "$c$s"; done
    case "$db" in
      */yum/history/*) sqlite3 -readonly -header -separator "$TAB" "$c" "SELECT b.tid, datetime(b.timestamp,'unixepoch') AS begin_utc, b.loginuid, c.cmdline, d.state, p.name, p.epoch||':'||p.version||'-'||p.release AS evr, p.arch FROM trans_beg b LEFT JOIN trans_cmdline c ON c.tid=b.tid LEFT JOIN trans_data_pkgs d ON d.tid=b.tid LEFT JOIN pkgtups p ON p.pkgtupid=d.pkgtupid ORDER BY b.tid;" > "$o/TRANSACTIONS-readable.tsv" 2>&1;;
      */dnf/history.sqlite*) sqlite3 -readonly -header -separator "$TAB" "$c" "SELECT t.id, datetime(t.dt_begin,'unixepoch') AS begin_utc, t.user_id, t.cmdline, ti.action, ti.repoid, r.name, r.epoch||':'||r.version||'-'||r.release AS evr, r.arch FROM trans t JOIN trans_item ti ON ti.trans_id=t.id LEFT JOIN rpm r ON r.item_id=ti.item_id ORDER BY t.id;" > "$o/TRANSACTIONS-readable.tsv" 2>&1
        echo "action codes (libdnf TransactionItemAction): 1 Install, 2 Downgrade, 3 Downgraded, 4 Obsolete, 5 Obsoleted, 6 Upgrade, 7 Upgraded, 8 Remove, 9 Reinstall, 10 Reinstalled, 11 Reason change" > "$o/ACTION-CODES.txt";;
    esac
    rm -f "${c:?}" "${c:?}-wal" "${c:?}-shm"
  done
  has dnf5 && { n=1; srv dnf5 -C history list > "$ITEM_OUT/dnf5-history-list.txt" 2>&1; }
  if has dnf; then n=1; srv dnf -C history list > "$ITEM_OUT/dnf-history-list.txt" 2>&1
    for id in $(awk '$1 ~ /^[0-9]+$/{print $1}' "$ITEM_OUT/dnf-history-list.txt" | head -n 300); do echo "==== $id"; srv dnf -C history info "$id" 2>&1; done > "$ITEM_OUT/dnf-history-info.txt"
  elif has yum; then n=1; srv yum -C history list all > "$ITEM_OUT/yum-history-list.txt" 2>&1
    for id in $(awk -F'|' '$1 ~ /^ *[0-9]+ *$/{gsub(/ /,"",$1); print $1}' "$ITEM_OUT/yum-history-list.txt" | head -n 300); do echo "==== $id"; srv yum -C history info "$id" 2>&1; done > "$ITEM_OUT/yum-history-info.txt"
  fi
  # yum.log on EL5-7 has no year: add the inferred year
  for f in /var/log/yum.log*; do [ -f "$f" ] || continue; n=1
    y=$(printf '%s' "$f" | sed -n 's/.*yum\.log-\([0-9]\{4\}\).*/\1/p'); [ -n "$y" ] || y=$(date -u -r "$f" +%Y)
    case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac 2>/dev/null | awk -v y="$y" -v f="$f" '{print f"\t"y" (inferred)\t"$0}'
  done > "$ITEM_OUT/yum-log-with-inferred-year.tsv"
  # apt history -> TSV
  for f in /var/log/apt/history.log*; do [ -f "$f" ] && { n=1; case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; }; done 2>/dev/null |
    awk 'BEGIN{print "start\tend\trequested_by\tcommandline\taction\tpackages"} /^Start-Date:/{s=substr($0,13)} /^End-Date:/{e=substr($0,11); for(k in A) print s"\t"e"\t"r"\t"c"\t"k"\t"A[k]; delete A; r=c=""} /^Commandline:/{c=substr($0,14)} /^Requested-By:/{r=substr($0,15)} /^(Install|Upgrade|Remove|Purge|Downgrade|Reinstall):/{k=substr($0,1,index($0,":")-1); A[k]=substr($0,index($0,":")+2)}' > "$ITEM_OUT/apt-history.tsv"
  has snap && { n=1; srv snap changes > "$ITEM_OUT/snap-changes.txt" 2>&1; }
  has flatpak && { n=1; srv flatpak history > "$ITEM_OUT/flatpak-history.txt" 2>&1; }
  has zypper && [ -f /var/log/zypp/history ] && n=1
  rm_empty "$ITEM_OUT"
  [ $n = 0 ] && return 10; return 0
}
lang_packages() {
  printf 'name\tversion\tinstaller\tdirect_url\tinstalled_utc(mtime)\tlocation\n' > "$ITEM_OUT/python-dist-info.tsv"
  find / -xdev \( -path /proc -o -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o -type d \( -name '*.dist-info' -o -name '*.egg-info' \) -print 2>/dev/null | head -n 50000 | while read -r d; do
    b=${d##*/}; b=${b%.dist-info}; b=${b%.egg-info}; name=${b%%-[0-9]*}; ver=${b#"$name"-}
    ins=$(cat "$d/INSTALLER" 2>/dev/null | head -n 1); du=$(tr -d '\n' 2>/dev/null < "$d/direct_url.json" | cut -c1-300)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$ver" "${ins:--}" "${du:--}" "$(date -u -r "$d" +%FT%TZ)" "${d%/*}"
  done >> "$ITEM_OUT/python-dist-info.tsv"
  { printf 'name\tversion\tlocation\tinstalled_utc(mtime)\n'
    for p in /usr/lib/node_modules/*/package.json /usr/local/lib/node_modules/*/package.json /usr/lib/node_modules/@*/*/package.json /usr/local/lib/node_modules/@*/*/package.json /home/*/.npm-global/lib/node_modules/*/package.json /root/.npm-global/lib/node_modules/*/package.json; do
      [ -f "$p" ] && printf '%s\t%s\t%s\t%s\n' "$(sed -n 's/^  "name": *"\([^"]*\)".*/\1/p' "$p" | head -n 1)" "$(sed -n 's/^  "version": *"\([^"]*\)".*/\1/p' "$p" | head -n 1)" "${p%/package.json}" "$(date -u -r "$p" +%FT%TZ)"; done; } > "$ITEM_OUT/npm-global.tsv"
  ls -la --time-style=full-iso /var/lib/gems/*/specifications /usr/share/gems/specifications /usr/local/lib/ruby/gems/*/specifications /home/*/.gem/ruby/*/specifications /root/.gem/ruby/*/specifications > "$ITEM_OUT/ruby-gems.txt" 2>/dev/null
  ls -la --time-style=full-iso /root/.cargo/bin /home/*/.cargo/bin /root/go/bin /home/*/go/bin /usr/local/go/bin > "$ITEM_OUT/cargo-go-binaries.txt" 2>/dev/null
  cpo "$ITEM_OUT/files" /root/.cargo/.crates.toml /root/.cargo/.crates2.json /home/*/.cargo/.crates.toml /root/.config/composer/composer.json /home/*/.config/composer/composer.json /root/.composer/composer.json
  has snap && srv snap list --all > "$ITEM_OUT/snap-list.txt" 2>&1
  has flatpak && srv flatpak list --columns=application,version,origin,installation > "$ITEM_OUT/flatpak-list.txt" 2>&1
  find / -xdev \( -path /proc -o -path "$C0F_EXCL" \) -prune -o -type f -iname '*.AppImage' -print 2>/dev/null | head -n 1000 | while read -r a; do printf '%s\t%s\t%s\n' "$a" "$(sha "$a")" "$(stat -c %y "$a")"; done > "$ITEM_OUT/appimages.tsv"
  find / -xdev \( -path /proc -o -path "$C0F_EXCL" \) -prune -o -type d -name conda-meta -print 2>/dev/null | head -n 200 | while read -r c; do ls "$c"/*.json 2>/dev/null | sed "s|^|$c: |"; done > "$ITEM_OUT/conda-packages.txt"
  for f in "$ITEM_OUT"/*.tsv; do [ "$(wc -l < "$f")" -le 1 ] && rm -f "${f:?}"; done
  rm_empty "$ITEM_OUT"
  [ -n "$(ls "$ITEM_OUT" 2>/dev/null)" ] && return 0; return 10
}
unpackaged_executables() {
  pkg_index
  printf 'path\tsize\tmode\towner\tmtime\tctime\tbtime\tsha256\ttype\n'
  if [ ! -s "$C0F_TMP/pkgfiles.idx" ]; then echo "# no package database could be read: ownership cannot be decided" >&2; return 12; fi
  find /bin /sbin /usr/bin /usr/sbin /usr/local /usr/libexec /opt /srv /root /home /etc /tmp /var/tmp /dev/shm /var/www -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" \) -prune -o -type f -perm /111 -print 2>/dev/null > "$C0F_TMP/exe.list"
  # one pass: package file list in memory, each executable checked as-is and with/without the /usr prefix (merged /usr)
  awk -F'\t' 'NR==FNR{own[$1]=1; next} { f=$0; if (f in own) next; if (("/usr" f) in own) next; g=f; if (sub(/^\/usr/,"",g) && (g in own)) next; print }' \
    "$C0F_TMP/pkgfiles.idx" "$C0F_TMP/exe.list" | while read -r f; do
    printf '%s\t%s\n' "$(stat -c '%n%t%s%t%A%t%U%t%y%t%z%t%w' "$f" | sed "s/%t/$TAB/g")" "$(sha "$f")$TAB$(file -m "$C0F_MAGIC" -b "$f" 2>/dev/null | cut -c1-120)"
  done
  return 0
}
package_integrity() {
  n=0
  if [ -d /var/lib/dpkg/info ]; then n=1
    for f in /var/lib/dpkg/info/*.md5sums; do p=${f##*/}; p=${p%.md5sums}
      ( cd / && md5sum -c --quiet "$f" 2>&1 ) | sed "s|^|$p: |"
    done > "$ITEM_OUT/dpkg-md5-mismatch.txt"
    awk 'BEGIN{RS=""; FS="\n"} {p=""; for(i=1;i<=NF;i++){ if($i~/^Package: /)p=substr($i,10); if($i~/^ \//){split($i,a," "); print p"\t"a[1]"\t"a[2]} }}' /var/lib/dpkg/status | while IFS="$TAB" read -r p f m; do
      [ -f "$f" ] || { echo "$p	$f	MISSING"; continue; }; [ "$(md5sum "$f" | cut -c1-32)" = "$m" ] || echo "$p	$f	CHANGED (config file)"; done > "$ITEM_OUT/dpkg-conffiles-changed.tsv"
    has dpkg && srv dpkg --verify > "$ITEM_OUT/dpkg-verify.txt" 2>&1
  fi
  if has rpm && rpm_db_copy; then n=1; srv rpm --dbpath "$C0F_TMP/rpmdb" -Va > "$ITEM_OUT/rpm-Va.txt" 2>&1
    echo "legend: S size, M mode, 5 digest, D device, L link, U user, G group, T mtime, P capabilities; c = config file" > "$ITEM_OUT/rpm-Va-legend.txt"; fi
  has pacman && { n=1; srv pacman -Qkk > "$ITEM_OUT/pacman-Qkk.txt" 2>&1; }
  has apk && { n=1; srv apk audit --system > "$ITEM_OUT/apk-audit-system.txt" 2>&1; }
  rm_empty "$ITEM_OUT"
  [ $n = 0 ] && return 12; return 0
}
