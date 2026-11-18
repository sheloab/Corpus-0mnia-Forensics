# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D13 / D14 / D15 =======================
web_conf_files() { find /etc/nginx /usr/local/nginx/conf /usr/local/openresty/nginx/conf /etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/lighttpd /etc/caddy -type f 2>/dev/null; }
web_effective_config() {
  has nginx && { srv nginx -T > "$ITEM_OUT/nginx-T.txt" 2>&1; srv nginx -V > "$ITEM_OUT/nginx-V.txt" 2>&1; }
  for a in apache2ctl apachectl httpd; do has "$a" || continue
    srv "$a" -S > "$ITEM_OUT/$a-S.txt" 2>&1; srv "$a" -M > "$ITEM_OUT/$a-M.txt" 2>&1; srv "$a" -t -D DUMP_INCLUDES > "$ITEM_OUT/$a-includes.txt" 2>&1; srv "$a" -V > "$ITEM_OUT/$a-V.txt" 2>&1; break; done
  has php && { srv php -v > "$ITEM_OUT/php-v.txt" 2>&1; srv php -i > "$ITEM_OUT/php-i.txt" 2>&1; }
  rm_empty "$ITEM_OUT"; return 0
}
# log paths named in web server configs (nginx access_log/error_log, Apache CustomLog/ErrorLog/TransferLog, lighttpd, caddy)
web_log_paths() {
  { web_conf_files | while read -r f; do
      grep -hiE '^[[:space:]]*(access_log|error_log|CustomLog|ErrorLog|TransferLog|accesslog\.filename|server\.errorlog)[[:space:]=]' "$f" 2>/dev/null; done
    cat "$C0F_OUT/13_web_servers/effective-config/nginx-T.txt" 2>/dev/null | grep -iE '^[[:space:]]*(access_log|error_log)[[:space:]]'
  } | sed 's/#.*//' | awk '{for(i=2;i<=NF;i++){ g=$i; gsub(/[";]/,"",g); if (g ~ /^\//) {print g; break} }}' | sed 's/\${APACHE_LOG_DIR}/\/var\/log\/apache2/' | sort -u
}
web_logs_from_config() {
  printf 'path_from_config\texists\tunder_var_log\tsize\tmtime\n' > "$ITEM_OUT/found.tsv"
  : > "$C0F_TMP/weblogs.list"
  web_log_paths | while read -r p; do
    for f in "$p" "$p".* "$p"-*; do [ -f "$f" ] || continue
      case "$f" in /var/log/*) u=yes;; *) u=no; echo "$f" >> "$C0F_TMP/weblogs.list";; esac
      printf '%s\tyes\t%s\t%s\t%s\n' "$f" "$u" "$(stat -c %s "$f")" "$(stat -c %y "$f")" >> "$ITEM_OUT/found.tsv"
    done
    [ -e "$p" ] || printf '%s\tno\t-\t-\t-\n' "$p" >> "$ITEM_OUT/found.tsv"
  done
  [ "$(wc -l < "$ITEM_OUT/found.tsv")" -le 1 ] && return 10
  [ -s "$C0F_TMP/weblogs.list" ] && c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/files" -e "$C0F_EXCL" -L "$C0F_TMP/weblogs.list" 2>>"$C0F_TMP/copy-stderr.log"
  return 0
}
web_roots() {
  { web_conf_files | while read -r f; do grep -hiE '^[[:space:]]*(root|alias|DocumentRoot|Alias|server\.document-root)[[:space:]=]' "$f" 2>/dev/null; done
    cat "$C0F_OUT/13_web_servers/effective-config/nginx-T.txt" 2>/dev/null | grep -iE '^[[:space:]]*(root|alias)[[:space:]]'
  } | sed 's/#.*//' | awk '{for(i=2;i<=NF;i++){ g=$i; gsub(/[";]/,"",g); if (g ~ /^\//) {print g; break} }}'
  for d in /var/www /srv/www /srv/http /usr/share/nginx/html /var/lib/tomcat*/webapps /opt/lampp/htdocs /home/*/public_html; do [ -d "$d" ] && echo "$d"; done
}
webroot_inventory() {
  web_roots | sed 's:/*$::' | sort -u | while read -r r; do [ -d "$r" ] && echo "$r"; done > "$C0F_TMP/webroots"
  # drop roots that are inside another listed root
  awk '{a[NR]=$0} END{for(i=1;i<=NR;i++){k=1; for(j=1;j<=NR;j++) if(i!=j && index(a[i],a[j]"/")==1) k=0; if(k) print a[i]}}' "$C0F_TMP/webroots" > "$ITEM_OUT/webroots.txt"
  [ -s "$ITEM_OUT/webroots.txt" ] || { rm -f "${ITEM_OUT:?}/webroots.txt"; echo "no web root found"; return 10; }
  since=$(date -d "@$(( $(date +%s) - C0F_SINCE*86400 ))" '+%Y-%m-%d %H:%M:%S')
  printf 'path\tsize\tmode\towner\tmtime\tctime\tsha256\n' > "$ITEM_OUT/inventory.tsv"; : > "$C0F_TMP/webcopy.list"
  while read -r r; do
    find "$r" -xdev \( -path "$C0F_EXCL" -o -path "$C0F_KITDIR" -o -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null | while read -r f; do
      printf '%s\t%s\n' "$(stat -c '%n%t%s%t%A%t%U%t%y%t%z' "$f" | sed "s/%t/$TAB/g")" "$(sha "$f")" >> "$ITEM_OUT/inventory.tsv"
    done
    find "$r" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.jsp*' -o -iname '*.asp*' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.cgi' -o -iname '*.sh' -o -iname '*.rb' -o -iname '*.war' \) \( -newermt "$since" -o -newerct "$since" \) -print 2>/dev/null >> "$C0F_TMP/webcopy.list"
    find "$r" -xdev -type d \( -iname '*upload*' -o -iname 'tmp' -o -iname 'cache' -o -iname 'images' -o -iname 'files' \) -print 2>/dev/null | while read -r u; do
      find "$u" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.jsp*' -o -iname '*.asp*' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.cgi' -o -iname '*.sh' \) -print 2>/dev/null; done >> "$C0F_TMP/webcopy.list"
    find "$r" -xdev -type f \( -name '.env' -o -name '.env.*' -o -name 'wp-config.php' -o -name 'config.php' -o -name 'configuration.php' -o -name 'settings.php' -o -name 'database.yml' -o -name 'application.properties' -o -name '.htaccess' -o -name '.user.ini' -o -name 'web.config' \) -print 2>/dev/null >> "$C0F_TMP/webcopy.list"
  done < "$ITEM_OUT/webroots.txt"
  sort -u "$C0F_TMP/webcopy.list" > "$C0F_TMP/webcopy.sorted"
  [ -s "$C0F_TMP/webcopy.sorted" ] && c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/files" -e "$C0F_EXCL" -L "$C0F_TMP/webcopy.sorted" 2>>"$C0F_TMP/copy-stderr.log"
  echo "copied scripts changed since $since, all scripts in upload/tmp/cache folders, credential/.htaccess files: $(wc -l < "$C0F_TMP/webcopy.sorted")" > "$ITEM_OUT/README.txt"
  return 0
}
tomcat_inventory() {
  for b in /etc/tomcat* /opt/tomcat* /usr/share/tomcat* /var/lib/tomcat*; do [ -d "$b" ] || continue
    for w in "$b/webapps" "$b"/*/webapps; do [ -d "$w" ] && { echo "== $w"; ls -la --time-style=full-iso "$w"; find "$w" -maxdepth 1 -name '*.war' -exec sha256sum {} \; ; }; done
    for l in "$b/logs" "$b"/*/logs; do [ -d "$l" ] && cpo "$ITEM_OUT/logs" -R "$l"; done
  done > "$ITEM_OUT/webapps.txt" 2>&1
  return 0
}
mycnf_value() { cat /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/*.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /etc/my.cnf.d/*.cnf 2>/dev/null | sed 's/#.*//' | awk -F= -v k="$1" '{gsub(/[ \t]/,"",$1); gsub(/-/,"_",$1); if (tolower($1)==k) {v=$2; gsub(/^[ \t"]+|[ \t"]+$/,"",v); print v}}' | tail -n 1; }
mysql_datadir() { d=$(mycnf_value datadir); [ -n "$d" ] && echo "$d" || for x in /var/lib/mysql /var/lib/mariadb /usr/local/mysql/data; do [ -d "$x" ] && echo "$x" && break; done; }
pg_datadirs() { for d in /var/lib/pgsql/data /var/lib/pgsql/*/data /var/lib/postgresql/*/main /var/lib/postgres/data /usr/local/pgsql/data; do [ -f "$d/PG_VERSION" ] && echo "$d"; done; }
pg_conf_value() { grep -hE "^[[:space:]]*$1[[:space:]]*=" "$2"/postgresql.conf "$2"/postgresql.auto.conf /etc/postgresql/*/main/postgresql.conf 2>/dev/null | tail -n 1 | sed "s/^[^=]*=[[:space:]]*//; s/[[:space:]]*#.*//; s/'//g"; }
db_logs() {
  n=0; s="$ITEM_OUT/logging-settings.txt"; : > "$s"
  dd=$(mysql_datadir)
  if [ -n "$dd" ] || [ -d /etc/mysql ] || [ -f /etc/my.cnf ]; then n=1
    { echo "== MySQL/MariaDB (datadir=$dd)"; for k in log_error general_log general_log_file slow_query_log slow_query_log_file log_bin server_audit_logging server_audit_file_path audit_log_file; do echo "$k=$(mycnf_value "$k")"; done; } >> "$s"
    for k in log_error general_log_file slow_query_log_file server_audit_file_path audit_log_file; do v=$(mycnf_value "$k"); [ -n "$v" ] || continue; case "$v" in /*) ;; *) v="$dd/$v";; esac; echo "$v"; done > "$C0F_TMP/dblogs"
    ls "$dd"/*.err "$dd"/*.log "$dd"/server_audit.log* "$dd"/audit.log* "$dd"/*-slow.log 2>/dev/null >> "$C0F_TMP/dblogs"
    [ -s "$C0F_TMP/dblogs" ] && c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/mysql" -e "$C0F_EXCL" -L "$C0F_TMP/dblogs" 2>>"$C0F_TMP/copy-stderr.log"
  fi
  for d in $(pg_datadirs); do n=1
    ld=$(pg_conf_value log_directory "$d"); case "$ld" in '') ld=log;; esac; case "$ld" in /*) ;; *) ld="$d/$ld";; esac
    { echo "== PostgreSQL $d"; for k in logging_collector log_directory log_filename log_connections log_disconnections log_statement shared_preload_libraries pgaudit.log; do echo "$k=$(pg_conf_value "$k" "$d")"; done; } >> "$s"
    cpo "$ITEM_OUT/postgresql" -R "$ld" "$d/pg_log" "$d/pg_hba.conf" "$d/pg_ident.conf" "$d/postgresql.conf" "$d/postgresql.auto.conf"
  done
  for c in /etc/redis/redis.conf /etc/redis.conf /etc/redis/*.conf; do [ -f "$c" ] || continue; n=1
    lf=$(awk '$1=="logfile"{gsub(/"/,"",$2); print $2}' "$c"); { echo "== Redis $c"; grep -E '^(logfile|requirepass|bind|protected-mode|appendonly|dir|dbfilename|rename-command)' "$c" | sed 's/^requirepass .*/requirepass (set)/'; } >> "$s"
    [ -n "$lf" ] && cpo "$ITEM_OUT/redis" "$lf"
  done
  for c in /etc/mongod.conf /etc/mongodb.conf; do [ -f "$c" ] || continue; n=1
    lp=$(awk '/^[[:space:]]*path:/{print $2}' "$c" | head -n 1); { echo "== MongoDB $c"; grep -A3 -E '^(systemLog|auditLog|security|net):' "$c"; } >> "$s"
    [ -n "$lp" ] && cpo "$ITEM_OUT/mongodb" "$lp" "$lp".*
    ap=$(awk '/auditLog/{f=1} f && /path:/{print $2; exit}' "$c"); [ -n "$ap" ] && cpo "$ITEM_OUT/mongodb" "$ap"
  done
  for d in /var/log/elasticsearch /var/log/opensearch /var/log/clickhouse-server /var/log/cassandra /var/log/influxdb; do [ -d "$d" ] && { n=1; echo "== $d (already copied with /var/log)" >> "$s"; }; done
  [ $n = 0 ] && { rm -f "${s:?}"; return 12; }; return 0
}
db_change_logs() {
  dd=$(mysql_datadir); [ -n "$dd" ] || return 12
  b=$(mycnf_value log_bin); [ -n "$b" ] && case "$b" in /*) bd=${b%/*};; *) bd=$dd;; esac
  ls "${bd:-$dd}"/*bin.[0-9]* "${bd:-$dd}"/*bin.index "$dd"/binlog.[0-9]* "$dd"/binlog.index "$dd"/mysql-bin.* "$dd"/mariadb-bin.* "$dd"/*relay-bin* 2>/dev/null | sort -u > "$C0F_TMP/binlogs"
  [ -s "$C0F_TMP/binlogs" ] || { echo "binary logging not enabled or no binlog files"; return 10; }
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -L "$C0F_TMP/binlogs" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
db_wal() {
  n=0; for d in $(pg_datadirs); do for w in "$d/pg_wal" "$d/pg_xlog"; do [ -d "$w" ] && { cpo "$ITEM_OUT" -R "$w"; n=1; }; done; done
  [ $n = 0 ] && return 12; return 0
}
db_data_files() {
  n=0
  for c in /etc/redis/redis.conf /etc/redis.conf /etc/redis/*.conf; do [ -f "$c" ] || continue
    d=$(awk '$1=="dir"{gsub(/"/,"",$2); print $2}' "$c"); [ -n "$d" ] || d=/var/lib/redis
    cpo "$ITEM_OUT/redis" "$d"/*.rdb "$d"/*.aof "$d"/appendonlydir; n=1
  done
  for r in $(cat "$C0F_OUT/13_web_servers/webroot/webroots.txt" 2>/dev/null) /opt /srv; do
    [ -d "$r" ] && find "$r" -xdev -type f \( -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' \) -size -2G 2>/dev/null; done | head -n 2000 > "$C0F_TMP/sqlitefiles"
  [ -s "$C0F_TMP/sqlitefiles" ] && { c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/sqlite" -e "$C0F_EXCL" -L "$C0F_TMP/sqlitefiles" 2>>"$C0F_TMP/copy-stderr.log"; n=1; }
  for d in "$(mysql_datadir)" $(pg_datadirs) /var/lib/mongodb /var/lib/elasticsearch; do [ -n "$d" ] && [ -d "$d" ] && { echo "== $d"; du -sh "$d"; find "$d" -maxdepth 2 -type f -printf '%p\t%s\t%TY-%Tm-%Td %TT\n' | head -n 5000; n=1; }; done > "$ITEM_OUT/data-folder-listings.txt" 2>&1
  rm_empty "$ITEM_OUT"; [ $n = 0 ] && return 12; return 0
}
db_client_files() {
  n=0
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in .mysql_history .psql_history .rediscli_history .dbshell .mongorc.js .mongoshrc.js .sqlite_history .my.cnf .pgpass .mylogin.cnf .influx_history .cqlsh_history; do [ -f "$h/$f" ] && echo "$h/$f"; done
    [ -d "$h/.mongodb/mongosh" ] && echo "$h/.mongodb/mongosh"
  done > "$C0F_TMP/dbclient"
  [ -s "$C0F_TMP/dbclient" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/dbclient" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
user_mail_forward() {
  each_home | while IFS="$TAB" read -r u id h s; do for f in .forward .procmailrc .mailrc .muttrc .fetchmailrc; do [ -f "$h/$f" ] && echo "$h/$f"; done; done > "$C0F_TMP/mailfwd"
  [ -s "$C0F_TMP/mailfwd" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -L "$C0F_TMP/mailfwd" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
