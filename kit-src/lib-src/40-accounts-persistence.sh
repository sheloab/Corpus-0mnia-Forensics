# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D07 / D08 =======================
sessions_now() {
  for u in /var/run/utmp /run/utmp; do [ -f "$u" ] && { c0f-logins utmp "$u" > "$ITEM_OUT/utmp.tsv" 2>"$ITEM_OUT/utmp.stderr.txt"; break; }; done
  has loginctl && { srv loginctl list-sessions --no-pager > "$ITEM_OUT/loginctl-sessions.txt" 2>&1; srv loginctl list-users --no-pager > "$ITEM_OUT/loginctl-users.txt" 2>&1; }
  ps -eo pid,ppid,user:32,tty,lstart,args -ww | awk 'NR==1 || /sshd: |xrdp|Xvnc|vncserver|x11vnc|nxserver|teamviewer|anydesk|rustdesk|screen|tmux|mosh-server|telnetd|dropbear/' > "$ITEM_OUT/remote-session-processes.txt"
  ps -eo pid,ppid,user:32,tty,lstart,comm,args -ww | awk 'NR==1 || ($4!="?" && $9 ~ /^(bash|zsh|sh|ash|dash|ksh|mksh|fish|tcsh|csh)$/)' > "$ITEM_OUT/interactive-shells.txt"
  for p in /proc/[0-9]*; do e=$(tr '\0' '\n' 2>/dev/null < "$p/environ" | grep -E '^(SSH_CONNECTION|SSH_CLIENT)=' | tr '\n' ' '); [ -n "$e" ] && echo "${p##*/} $(cat "$p/comm") $e"; done > "$ITEM_OUT/ssh-connection-env.txt"
  rm_empty "$ITEM_OUT"
  return 0
}
logins_parse() {
  n=0
  for f in /var/run/utmp /run/utmp /var/log/wtmp* /var/log/btmp*; do
    [ -f "$f" ] || continue; b=$(safe "${f#/}")
    case "$f" in *.gz) zcat "$f" > "$C0F_TMP/lg.raw" 2>/dev/null; src="$C0F_TMP/lg.raw";; *.xz) xz -dc "$f" > "$C0F_TMP/lg.raw" 2>/dev/null; src="$C0F_TMP/lg.raw";; *) src=$f;; esac
    c0f-logins utmp "$src" > "$ITEM_OUT/$b.tsv" 2>>"$ITEM_OUT/parser.log" && n=$((n+1))
    rm -f "${C0F_TMP:?}/lg.raw"
  done
  [ -f /var/log/lastlog ] && { c0f-logins lastlog -p /etc/passwd /var/log/lastlog > "$ITEM_OUT/lastlog.tsv" 2>>"$ITEM_OUT/parser.log"; n=$((n+1)); }
  [ -f /var/log/faillog ] && { c0f-logins faillog -p /etc/passwd /var/log/faillog > "$ITEM_OUT/faillog.tsv" 2>>"$ITEM_OUT/parser.log"; n=$((n+1)); }
  if [ $n -gt 0 ]; then
    { printf 'file\trec\ttime_utc\tanomaly\n'
      for t in "$ITEM_OUT"/*tmp*.tsv; do [ -f "$t" ] && awk -F'\t' -v f="${t##*/}" 'NR>1 && $15!="-" && $15!=""{print f"\t"$1"\t"$14"\t"$15}' "$t"; done; } > "$ITEM_OUT/anomalies.tsv"
    [ "$(wc -l < "$ITEM_OUT/anomalies.tsv")" -le 1 ] && echo "no anomalies in login records" > "$ITEM_OUT/anomalies.tsv"
  fi
  [ $n = 0 ] && { echo "no classic login record files (wtmpdb/lastlog2 systems: see D07-012/013)"; return 11; }; return 0
}
users_table() {
  st="$C0F_TMP/users"; mk "$st"
  umin=$(awk '$1=="UID_MIN"{print $2}' /etc/login.defs 2>/dev/null); umin=${umin:-1000}
  cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/#.*//' | grep -vE '^[[:space:]]*$|^[[:space:]]*(Defaults|Cmnd_Alias|Host_Alias|Runas_Alias|User_Alias)' > "$st/sudo-rules"
  ll="$C0F_OUT/07_accounts_auth/logins/lastlog.tsv"
  [ -r /etc/passwd ] || return 11
  printf 'user,uid,gid,gecos,home,shell,type,password_status,hash_algorithm,last_password_change,min_days,max_days,warn_days,inactive_days,account_expires,expired,primary_group,groups,sudo,sudo_nopasswd,uid0,home_exists,home_owner,home_mode,authorized_keys,authorized_keys_with_options,crontab,running_processes,last_login_utc,last_login_from\n' > "$ITEM_OUT/users.csv"
  today=$(( $(date +%s) / 86400 ))
  q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"; }
  awk -F: '{print $1"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7}' /etc/passwd | while IFS="$TAB" read -r u uid gid gecos home shell; do
    sh=$(awk -F: -v u="$u" '$1==u{print; exit}' /etc/shadow 2>/dev/null)
    pw=$(printf '%s' "$sh" | cut -d: -f2); lc=$(printf '%s' "$sh" | cut -d: -f3); mn=$(printf '%s' "$sh" | cut -d: -f4); mx=$(printf '%s' "$sh" | cut -d: -f5)
    wn=$(printf '%s' "$sh" | cut -d: -f6); ina=$(printf '%s' "$sh" | cut -d: -f7); exp=$(printf '%s' "$sh" | cut -d: -f8)
    case "$pw" in '') pst=EMPTY_NO_PASSWORD;; '!'|'!!'|'*'|'!*'|'*LK*') pst=NO_PASSWORD_SET_OR_LOCKED;; '!'*) pst=LOCKED;; '*'*) pst=DISABLED;; *) pst=ACTIVE;; esac
    [ -z "$sh" ] && pst=NO_SHADOW_ENTRY
    case "$pw" in '!'*) h=${pw#!};; *) h=$pw;; esac
    case "$h" in '$y$'*) alg=yescrypt;; '$gy$'*) alg=gost-yescrypt;; '$7$'*) alg=scrypt;; '$2'?'$'*) alg=bcrypt;; '$6$'*) alg=sha512crypt;; '$5$'*) alg=sha256crypt;; '$1$'*) alg=MD5-WEAK;; '$'*) alg=other;; ''|'*'|'!'|'!!'|'*LK*') alg=-;; *) alg=DES-WEAK;; esac
    lcd=$lc; case "$lc" in ''|0|*[!0-9]*) ;; *) lcd=$(date -u -d "@$((lc*86400))" +%F);; esac
    expd=never; expired=no
    case "$exp" in ''|*[!0-9]*) ;; *) expd=$(date -u -d "@$((exp*86400))" +%F); [ "$exp" -lt "$today" ] && expired=YES;; esac
    case "$shell" in */nologin|*/false|'') stype=no-login;; *) stype=login;; esac
    if [ "$uid" = 0 ]; then typ=root; elif [ "$uid" -ge "$umin" ] 2>/dev/null && [ "$uid" != 65534 ]; then typ=human; else typ=system; fi
    [ "$stype" = login ] && [ "$typ" = system ] && typ="system-with-login-shell"
    pg=$(awk -F: -v g="$gid" '$3==g{print $1; exit}' /etc/group)
    grps=$(awk -F: -v u="$u" '{n=split($4,m,","); for(i=1;i<=n;i++) if(m[i]==u) print $1}' /etc/group | tr '\n' ' ' | sed 's/ $//')
    allg="$pg $grps"; sudo=no; nop=no
    for g in $allg; do case "$g" in sudo|wheel|admin) sudo="yes(group $g)";; esac; done
    if grep -qE "(^|[[:space:],])$u([[:space:],]|$)" "$st/sudo-rules" 2>/dev/null; then sudo="yes(sudoers)"; grep -E "(^|[[:space:],])$u([[:space:],]|$)" "$st/sudo-rules" | grep -q NOPASSWD && nop=yes; fi
    for g in $allg; do grep -qE "%$g([[:space:],]|$)" "$st/sudo-rules" 2>/dev/null && { sudo="yes(sudoers %$g)"; grep -E "%$g([[:space:],]|$)" "$st/sudo-rules" | grep -q NOPASSWD && nop=yes; }; done
    he=no; ho=""; hm=""; [ -d "$home" ] && { he=yes; ho=$(stat -c %U "$home"); hm=$(stat -c %a "$home"); }
    ak=0; ako=0
    for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$k" ] || continue
      ak=$((ak + $(grep -cvE '^[[:space:]]*(#|$)' "$k"))); ako=$((ako + $(grep -cvE '^[[:space:]]*(#|$|(ssh|ecdsa|sk)-)' "$k")))
    done
    ct=no; for c in "/var/spool/cron/crontabs/$u" "/var/spool/cron/$u" "/var/spool/cron/tabs/$u"; do [ -f "$c" ] && ct=yes; done
    np=$(ps -o user= -e 2>/dev/null | grep -cx "$u")
    lt=""; lf=""
    [ -f "$ll" ] && { lt=$(awk -F'\t' -v u="$u" '$2==u{print $3; exit}' "$ll"); lf=$(awk -F'\t' -v u="$u" '$2==u{print $5; exit}' "$ll"); }
    echo "$(q "$u"),$uid,$gid,$(q "$gecos"),$(q "$home"),$(q "$shell"),$typ,$pst,$alg,$lcd,$mn,$mx,$wn,$ina,$expd,$expired,$(q "$pg"),$(q "$grps"),$(q "$sudo"),$nop,$( [ "$uid" = 0 ] && echo yes || echo no),$he,$ho,$hm,$ak,$ako,$ct,$np,$lt,$(q "$lf")" >> "$ITEM_OUT/users.csv"
  done
  printf 'group,gid,members,privileged\n' > "$ITEM_OUT/groups.csv"
  awk -F: '{p="no"; if($1 ~ /^(root|sudo|wheel|admin|adm|docker|lxd|incus|disk|shadow|kvm|libvirt|systemd-journal|video|input)$/) p="yes"; printf "\"%s\",%s,\"%s\",%s\n",$1,$3,$4,p}' /etc/group >> "$ITEM_OUT/groups.csv"
  since_d=$(date -u -d "@$(( $(date +%s) - C0F_SINCE*86400 ))" +%F)
  { echo "== UID 0 accounts other than root"; awk -F: '$3==0 && $1!="root"{print}' /etc/passwd
    echo "== duplicate UIDs"; awk -F: '{c[$3]++; n[$3]=n[$3]" "$1} END{for(u in c) if(c[u]>1) print u":"n[u]}' /etc/passwd
    echo "== duplicate GIDs"; awk -F: '{c[$3]++; n[$3]=n[$3]" "$1} END{for(u in c) if(c[u]>1) print u":"n[u]}' /etc/group
    echo "== accounts with an EMPTY password"; grep ',EMPTY_NO_PASSWORD,' "$ITEM_OUT/users.csv"
    echo "== system accounts with a login shell"; grep ',system-with-login-shell,' "$ITEM_OUT/users.csv"
    echo "== weak password hashes (MD5/DES)"; grep -E ',(MD5|DES)-WEAK,' "$ITEM_OUT/users.csv"
    echo "== members of root-equivalent groups (docker, lxd, incus, disk, sudo, wheel, admin)"; awk -F: '$1 ~ /^(docker|lxd|incus|disk|sudo|wheel|admin)$/ && $4!=""{print $1": "$4}' /etc/group
    echo "== NOPASSWD sudo rules"; grep -n NOPASSWD "$st/sudo-rules"
    echo "== password changed within $C0F_SINCE days (since $since_d)"; awk -F: -v t=$(( $(date +%s)/86400 - C0F_SINCE )) '$3+0>=t{print $1}' /etc/shadow 2>/dev/null
    echo "== expired accounts"; grep ',YES,' "$ITEM_OUT/users.csv"
    echo "== homes without a passwd entry"; for h in /home/*; do [ -d "$h" ] && ! awk -F: -v h="$h" '$6==h{f=1} END{exit !f}' /etc/passwd && echo "$h"; done
    echo "== /etc/passwd vs /etc/passwd- (previous version)"; [ -f /etc/passwd- ] && diff /etc/passwd- /etc/passwd
    echo "== /etc/group vs /etc/group- (previous version)"; [ -f /etc/group- ] && diff /etc/group- /etc/group
    echo "== account management evidence in logs (useradd/adduser/usermod/userdel/groupadd/passwd)"
    for f in /var/log/auth.log* /var/log/secure*; do [ -f "$f" ] || continue; case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac 2>/dev/null | grep -aE 'useradd|adduser|usermod|userdel|groupadd|groupmod|gpasswd|chpasswd|passwd\[' | sed "s|^|$f: |"; done
  } > "$ITEM_OUT/findings.txt" 2>/dev/null
  rm -rf "${st:?}"; return 0
}
pam_modules_check() {
  printf 'module\tpath\tsha256\tsize\tmtime\tctime\tin_standard_dir\treferenced_in\n'
  grep -rhoE 'pam_[A-Za-z0-9_]+\.so|/[^ ]+\.so' /etc/pam.d /etc/pam.conf 2>/dev/null | sort -u | while read -r m; do
    refs=$(grep -rl -- "$m" /etc/pam.d /etc/pam.conf 2>/dev/null | tr '\n' ' ')
    case "$m" in /*) cands=$m;; *) cands=$(ls -d /lib/security/"$m" /lib64/security/"$m" /usr/lib/security/"$m" /usr/lib64/security/"$m" /lib/*-linux-gnu*/security/"$m" /usr/lib/*-linux-gnu*/security/"$m" 2>/dev/null);; esac
    hit=0; for p in $cands; do [ -f "$p" ] || continue; hit=1
      case "$p" in /lib/security/*|/lib64/security/*|/usr/lib/security/*|/usr/lib64/security/*|/lib/*-linux-gnu*/security/*|/usr/lib/*-linux-gnu*/security/*) std=yes;; *) std=NO;; esac
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$m" "$p" "$(sha "$p")" "$(stat -c %s "$p")" "$(stat -c %y "$p")" "$(stat -c %z "$p")" "$std" "$refs"; done
    [ $hit = 0 ] && printf '%s\t(not found)\t-\t-\t-\t-\t-\t%s\n' "$m" "$refs"
  done
  echo; echo "# security module folders, newest files first:"
  for d in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/*-linux-gnu*/security /usr/lib/*-linux-gnu*/security; do [ -d "$d" ] && ls -lt --time-style=full-iso "$d" 2>/dev/null | head -n 15 | sed "s|^|$d: |"; done
  return 0
}
ssh_user_files() {
  each_home | while IFS="$TAB" read -r u id h s; do
    [ -d "$h/.ssh" ] && { cpo "$ITEM_OUT/$(safe "$u")" -R "$h/.ssh"; echo "$u $h/.ssh"; }
  done > "$ITEM_OUT/users-with-ssh.txt"
  { echo "# ssh-agent / forwarded agent sockets in process environments"
    for p in /proc/[0-9]*; do tr '\0' '\n' 2>/dev/null < "$p/environ" | grep '^SSH_AUTH_SOCK=' | sed "s|^|pid ${p##*/} $(cat "$p/comm" 2>/dev/null) |"; done | sort -u
    ls -la /tmp/ssh-* 2>/dev/null; } > "$ITEM_OUT/agents.txt"
  [ -s "$ITEM_OUT/users-with-ssh.txt" ] && return 0
  rm -f "${ITEM_OUT:?}/users-with-ssh.txt"; return 10
}
ssh_key_inventory() {
  {
    ls /etc/ssh/ssh_host_* /etc/ssh/*.pub /etc/ssh/ssh_known_hosts /etc/ssh/*_ca* /etc/ssh/authorized_keys* 2>/dev/null
    each_home | while IFS="$TAB" read -r u id h s; do [ -d "$h/.ssh" ] && find "$h/.ssh" -maxdepth 2 -type f 2>/dev/null; done
    grep -hE '^[[:space:]]*(AuthorizedKeysFile|TrustedUserCAKeys|RevokedKeys|HostKey)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{for(i=2;i<=NF;i++) print $i}' | grep '^/'
  } | sort -u > "$C0F_TMP/sshkeyfiles"
  [ -s "$C0F_TMP/sshkeyfiles" ] || return 10
  tr '\n' '\0' < "$C0F_TMP/sshkeyfiles" | xargs -0 c0f-sshkey 2>&1 | awk 'NR==1 || !/^file\tline\t/'
  return 0
}
rhosts_check() {
  f=0
  for p in /etc/hosts.equiv /etc/shosts.equiv $(each_home | cut -f3 | sed 's|$|/.rhosts|') $(each_home | cut -f3 | sed 's|$|/.shosts|'); do
    [ -f "$p" ] && { echo "== $p"; ls -la --time-style=full-iso "$p"; cat "$p"; f=1; }
  done
  [ $f = 0 ] && echo "none found"; return 0
}
user_systemd_units() {
  n=0
  for h in $(each_home | cut -f3); do [ -d "$h/.config/systemd" ] && { cpo "$ITEM_OUT" -R "$h/.config/systemd"; n=1; }; done
  [ -d /var/lib/systemd/linger ] && cpo "$ITEM_OUT" -R /var/lib/systemd/linger
  [ $n = 0 ] && return 10; return 0
}
user_dotfiles() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in "$h"/.[!.]* "$h"/..?*; do [ -f "$f" ] && echo "$f"; done
    for d in .config/autostart .local/bin .bashrc.d .profile.d .config/fish .config/environment.d .oh-my-zsh/custom; do [ -d "$h/$d" ] && echo "$h/$d"; done
  done > "$C0F_TMP/dotlist"
  [ -s "$C0F_TMP/dotlist" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -e "$C0F_KITDIR" -R -L "$C0F_TMP/dotlist" 2>>"$C0F_TMP/copy-stderr.log"
  return 0
}
ld_preload_check() {
  f=/etc/ld.so.preload
  echo "stat: $(stat -c '%n size=%s mode=%A mtime=%y ctime=%z' "$f" 2>&1)"
  echo "test -e: $([ -e "$f" ] && echo exists || echo absent)"
  echo "readdir of /etc lists ld.so.preload: $(ls -a /etc | grep -cx ld.so.preload)"
  echo "find: $(find /etc -maxdepth 1 -name ld.so.preload 2>/dev/null)"
  echo "content (cat):"; cat "$f" 2>&1
  echo "content (dd | od):"; dd if="$f" bs=4096 count=16 2>/dev/null | od -c | head -n 40
  echo; echo "== processes with LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT in their environment"
  for p in /proc/[0-9]*; do e=$(tr '\0' '\n' 2>/dev/null < "$p/environ" | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)=' | tr '\n' ' '); [ -n "$e" ] && echo "${p##*/} $(cat "$p/comm" 2>/dev/null) $e"; done
  echo; echo "== shared libraries mapped from unusual paths (count of processes)"
  cat /proc/[0-9]*/maps 2>/dev/null | awk '$6 ~ /\.so/ && $6 !~ /^\/(usr\/)?(lib|lib64|lib32|libx32)\// {print $6}' | sort | uniq -c | sort -rn | head -n 50
  return 0
}
immutable_attr_scan() {
  for d in /etc /usr/bin /usr/sbin /bin /sbin /usr/lib/systemd /lib/systemd /root /home /var/spool/cron /var/www /srv /opt /tmp /var/tmp /usr/local; do
    [ -d "$d" ] || continue
    lsattr -R -a "$d" 2>/dev/null | awk '$1 ~ /[ia]/ && $1 !~ /^-+$/ {print}' | awk '{ split($1,a,""); f=0; for(i in a) if(a[i]=="i"||a[i]=="a") f=1; if(f) print }'
  done
  return 0
}
git_hooks_scan() {
  find /var/www /srv /opt /home /root /usr/local /etc -xdev -maxdepth 6 -type d -name .git 2>/dev/null | head -n 500 > "$ITEM_OUT/repos.txt"
  [ -s "$ITEM_OUT/repos.txt" ] || { rm -f "${ITEM_OUT:?}/repos.txt"; return 10; }
  while read -r g; do cpo "$ITEM_OUT/repos" -R "$g/hooks" "$g/config" "$g/HEAD" "$g/ORIG_HEAD" "$g/FETCH_HEAD" "$g/logs" "$g/packed-refs"; done < "$ITEM_OUT/repos.txt"
  return 0
}
