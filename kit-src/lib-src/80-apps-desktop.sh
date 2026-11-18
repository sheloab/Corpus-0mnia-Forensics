# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D16 / D17 =======================
shell_histories() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in .bash_history .zsh_history .zhistory .ash_history .sh_history .history .ksh_history .mksh_history .tcsh_history .local/share/fish/fish_history .python_history .node_repl_history .mysql_history .psql_history .sqlite_history .rediscli_history .lesshst .viminfo .wget-hsts .irb_history .pry_history .Rhistory .julia/logs/repl_history.jl .scala_history .gdb_history .ipython/profile_default/history.sqlite .local/share/nvim/shada/main.shada .bash_sessions; do
      [ -e "$h/$f" ] && echo "$h/$f"; done
  done > "$C0F_TMP/hist"
  { echo "# per account: history file state and HISTFILE settings in start-up files"
    each_home | while IFS="$TAB" read -r u id h s; do
      for f in "$h/.bash_history" "$h/.zsh_history" "$h/.ash_history"; do
        if [ -L "$f" ]; then echo "$u $f SYMLINK -> $(readlink "$f")"; elif [ -f "$f" ]; then echo "$u $f size=$(stat -c %s "$f") mtime=$(stat -c %y "$f")"; fi; done
      case "$s" in */nologin|*/false) ;; *) [ -e "$h/.bash_history" ] || [ -e "$h/.zsh_history" ] || [ -e "$h/.ash_history" ] || echo "$u has a login shell ($s) but NO history file";; esac
      grep -HnE 'HISTFILE|HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTIGNORE|set \+o history|unset HISTFILE' "$h"/.bashrc "$h"/.bash_profile "$h"/.profile "$h"/.zshrc "$h"/.bash_logout 2>/dev/null
    done
    grep -HnE 'HISTFILE|HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTIGNORE|unset HISTFILE|history -c' /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/zsh/* /etc/environment 2>/dev/null
    echo "# running processes with HISTFILE set to /dev/null or empty"
    for p in /proc/[0-9]*; do tr '\0' '\n' 2>/dev/null < "$p/environ" | grep -E '^HISTFILE=(/dev/null)?$|^HISTSIZE=0$' | sed "s|^|pid ${p##*/} $(cat "$p/comm" 2>/dev/null) |"; done
  } > "$ITEM_OUT/history-tampering.txt" 2>/dev/null
  [ -s "$C0F_TMP/hist" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/hist" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
user_app_artifacts() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in .aws .azure .config/gcloud .kube .docker/config.json .netrc .git-credentials .gitconfig .config/git .config/rclone .filezilla .config/filezilla .npmrc .pypirc .local/share/recently-used.xbel .local/share/Trash/info .s3cfg .boto .terraform.d .config/doctl .config/hcloud .oci .ssh/config .config/gh .vault-token .pgpass .my.cnf; do
      [ -e "$h/$f" ] && echo "$h/$f"; done
    [ -d "$h/.gnupg" ] && { find "$h/.gnupg" -maxdepth 1 -type f \( -name 'pubring*' -o -name 'trustdb.gpg' -o -name 'gpg.conf' -o -name 'gpg-agent.conf' \) 2>/dev/null; }
  done > "$C0F_TMP/apps"
  [ -s "$C0F_TMP/apps" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/apps" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
remote_access_tools() {
  : > "$C0F_TMP/rat"; : > "$ITEM_OUT/found.txt"
  for p in /etc/anydesk /var/log/anydesk.trace /var/lib/anydesk /opt/teamviewer /etc/teamviewer /var/log/teamviewer* /opt/rustdesk /usr/lib/rustdesk /usr/NX/etc /usr/NX/var/log /var/log/nxserver.log /opt/google/chrome-remote-desktop /etc/chrome-remote-desktop-session /opt/screenconnect* /opt/connectwisecontrol* /opt/splashtop* /etc/frp /etc/frpc.ini /etc/frps.ini /etc/cloudflared /root/.cloudflared /etc/ngrok* /root/.config/ngrok /root/.ngrok2 /usr/local/bin/ngrok /usr/local/bin/frpc /usr/local/bin/chisel /usr/local/bin/cloudflared /usr/local/bin/rclone /usr/bin/rclone /etc/meshagent* /usr/local/mesh_services /opt/zerotier /var/lib/zerotier-one; do
    [ -e "$p" ] && { echo "$p" >> "$C0F_TMP/rat"; echo "present: $p" >> "$ITEM_OUT/found.txt"; }
  done
  each_home | while IFS="$TAB" read -r u id h s; do for f in .anydesk .config/teamviewer .config/rustdesk .nx .config/ngrok .ngrok2 .cloudflared .config/rclone .megarc .config/chrome-remote-desktop; do [ -e "$h/$f" ] && { echo "$h/$f" >> "$C0F_TMP/rat"; echo "present: $h/$f" >> "$ITEM_OUT/found.txt"; }; done; done
  ps -eo pid,user:32,lstart,args -ww | grep -iE 'anydesk|teamviewer|rustdesk|nxserver|nxnode|chrome-remote|screenconnect|splashtop|ngrok|frpc|frps|chisel|cloudflared|tailscaled|zerotier|rclone|meshagent|gotty|ttyd|socat|ncat|netcat|nc -l' | grep -v ' grep ' | sed 's/^/running: /' >> "$ITEM_OUT/found.txt"
  [ -s "$C0F_TMP/rat" ] && c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/files" -e "$C0F_EXCL" -R -L "$C0F_TMP/rat" 2>>"$C0F_TMP/copy-stderr.log"
  [ -s "$ITEM_OUT/found.txt" ] && return 0; rm -f "${ITEM_OUT:?}/found.txt"; return 10
}
dev_tool_artifacts() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in .vscode-server .vscode-oss-server; do [ -d "$h/$f" ] && find "$h/$f" -maxdepth 3 \( -name '*.log' -o -name 'settings.json' -o -name 'extensions.json' -o -name '.cli*' \) -type f 2>/dev/null | head -n 500; done
    [ -d "$h/.local/share/jupyter/runtime" ] && echo "$h/.local/share/jupyter/runtime"
    [ -d "$h/.jupyter" ] && echo "$h/.jupyter"
  done > "$C0F_TMP/devtools"
  [ -s "$C0F_TMP/devtools" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/devtools" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
tmux_screen_buffers() {
  n=0
  for s in /tmp/tmux-*/* /run/user/*/tmux-*/*; do [ -S "$s" ] || continue; n=1
    o="$ITEM_OUT/tmux_$(safe "$s")"; mk "$o"
    srv tmux -S "$s" list-sessions > "$o/sessions.txt" 2>&1; srv tmux -S "$s" list-windows -a > "$o/windows.txt" 2>&1
    srv tmux -S "$s" list-buffers > "$o/buffers.txt" 2>&1
    i=0; for b in $(srv tmux -S "$s" list-buffers -F '#{buffer_name}' 2>/dev/null); do srv tmux -S "$s" show-buffer -b "$b" > "$o/buffer_$(safe "$b").txt" 2>&1; done
    for pn in $(srv tmux -S "$s" list-panes -a -F '#{session_name}:#{window_index}.#{pane_index}' 2>/dev/null); do srv tmux -S "$s" capture-pane -p -S - -t "$pn" > "$o/pane_$(safe "$pn").txt" 2>&1; done
  done
  for d in /run/screen /var/run/screen /tmp/screens; do [ -d "$d" ] && { ls -laR "$d" > "$ITEM_OUT/screen-sockets.txt" 2>&1; n=1; }; done
  [ -f /tmp/screen-exchange ] && { cpo "$ITEM_OUT" /tmp/screen-exchange; n=1; }
  [ $n = 0 ] && return 12; return 0
}
# x_displays: "num<TAB>socket<TAB>auth_file<TAB>owner" for every X11 display found
x_displays() {
  for s in /tmp/.X11-unix/X*; do [ -S "$s" ] || continue; n=${s##*/X}; a=""
    for p in /proc/[0-9]*; do c=$(tr '\0' ' ' 2>/dev/null < "$p/cmdline"); case "$c" in *X*" :$n "*|*X*" :$n") a=$(printf '%s' "$c" | sed -n 's/.* -auth \([^ ]*\).*/\1/p'); [ -n "$a" ] && break;; esac; done
    if [ -z "$a" ] || [ ! -r "$a" ]; then
      for p in /proc/[0-9]*; do e=$(tr '\0' '\n' 2>/dev/null < "$p/environ"); printf '%s' "$e" | grep -qx "DISPLAY=:$n\(\.0\)\?" || continue
        a=$(printf '%s' "$e" | sed -n 's/^XAUTHORITY=//p'); [ -n "$a" ] && [ -r "$a" ] && break
        u=$(stat -c %U "$p"); hh=$(awk -F: -v u="$u" '$1==u{print $6}' /etc/passwd); [ -r "$hh/.Xauthority" ] && { a="$hh/.Xauthority"; break; }
      done
    fi
    printf '%s\t%s\t%s\t%s\n' "$n" "$s" "${a:--}" "$(stat -c %U "$s" 2>/dev/null)"
  done
}
gui_detect() {
  echo "== X11 displays (num socket auth owner)"; x_displays
  echo "== Wayland sockets"; ls -la /run/user/*/wayland-* 2>/dev/null
  echo "== display managers / remote desktop processes"; ps -eo pid,user:32,args -ww | grep -E 'gdm|lightdm|sddm|xdm|lxdm|Xorg|Xwayland|Xvnc|Xtigervnc|x11vnc|xrdp|nxserver|gnome-shell|kwin|xfce4-session|mate-session|cinnamon' | grep -v ' grep '
  echo "== default target"; srv systemctl get-default 2>/dev/null
  return 0
}
x11_each() { # x11_each SUBCOMMAND : runs c0f-x11 for every display, writes into $ITEM_OUT
  found=0
  x_displays > "$C0F_TMP/xd"
  while IFS="$TAB" read -r n s a o; do found=1
    aopt=""; [ "$a" != - ] && aopt="-a $a"
    case "$1" in
      clipboard) c0f-x11 -d ":$n" $aopt -t 10 clipboard "$ITEM_OUT/display_$n" > "$ITEM_OUT/display_$n.clipboard.tsv" 2>"$ITEM_OUT/display_$n.log";;
      windows) c0f-x11 -d ":$n" $aopt -t 20 windows > "$ITEM_OUT/display_$n.tsv" 2>"$ITEM_OUT/display_$n.log"; c0f-x11 -d ":$n" $aopt info > "$ITEM_OUT/display_$n.info.txt" 2>&1;;
      screenshot) c0f-x11 -d ":$n" $aopt -t 60 screenshot "$ITEM_OUT/display_$n.png" 2>"$ITEM_OUT/display_$n.log";;
    esac
    rc=$?; case $rc in 0) sub OK - "display :$n";; 3) sub DENIED PERMISSION_DENIED "display :$n (auth $a)";; *) sub FAILED EXIT_NONZERO "display :$n rc=$rc";; esac
  done < "$C0F_TMP/xd"
  rm_empty "$ITEM_OUT"; [ $found = 0 ] && return 12; return 0
}
x11_clipboard() {
  x11_each clipboard; r=$?
  for u in /run/user/*; do [ -S "$u/wayland-0" ] || continue; has wl-paste || break
    uid=${u##*/}; WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=$u srv wl-paste --list-types > "$ITEM_OUT/wayland_$uid.types.txt" 2>&1
    WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=$u srv wl-paste --no-newline > "$ITEM_OUT/wayland_$uid.clipboard.bin" 2>/dev/null; r=0; done
  for h in $(each_home | cut -f3); do for f in .local/share/xfce4/clipman/textsrc .config/copyq .local/share/gpaste .local/share/klipper .local/share/diodon; do [ -e "$h/$f" ] && cpo "$ITEM_OUT/clipboard-managers" -R "$h/$f"; done; done
  return $r
}
x11_windows() { x11_each windows; }
x11_screenshots() { x11_each screenshot; }
browser_artifacts() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for prof in "$h"/.mozilla/firefox/*/ "$h"/snap/firefox/common/.mozilla/firefox/*/ "$h"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/; do [ -d "$prof" ] || continue
      for f in places.sqlite places.sqlite-wal cookies.sqlite cookies.sqlite-wal formhistory.sqlite downloads.sqlite logins.json key4.db key3.db extensions.json addons.json sessionstore.jsonlz4 sessionstore-backups prefs.js handlers.json permissions.sqlite favicons.sqlite; do [ -e "$prof$f" ] && echo "$prof$f"; done; done
    for base in .config/google-chrome .config/chromium .config/BraveSoftware/Brave-Browser .config/microsoft-edge .config/opera .config/vivaldi snap/chromium/common/chromium; do
      for prof in "$h/$base"/Default/ "$h/$base"/Profile*/; do [ -d "$prof" ] || continue
        for f in History History-journal Cookies Network/Cookies "Login Data" "Web Data" Bookmarks Preferences "Secure Preferences" "Top Sites" Shortcuts "Visited Links" "Last Session" "Current Session" Sessions "Extension State" Extensions; do
          [ -e "$prof$f" ] && { [ "$f" = Extensions ] && ls -la "$prof$f" > /dev/null 2>&1; echo "$prof$f"; }; done; done
      [ -f "$h/$base/Local State" ] && echo "$h/$base/Local State"
    done
  done | grep -v '/Extensions$' > "$C0F_TMP/br"
  each_home | while IFS="$TAB" read -r u id h s; do for e in "$h"/.config/*/Default/Extensions "$h"/.config/*/*/Default/Extensions "$h"/.config/*/Profile*/Extensions; do [ -d "$e" ] && find "$e" -maxdepth 3 -name manifest.json 2>/dev/null; done; done >> "$C0F_TMP/br"
  [ -s "$C0F_TMP/br" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/br" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
desktop_user_artifacts() {
  each_home | while IFS="$TAB" read -r u id h s; do
    for f in .local/share/recently-used.xbel .recently-used .local/share/Trash .cache/thumbnails .thumbnails .config/autostart .local/share/keyrings .local/share/kwalletd .kde/share/apps/kwallet .config/kdeglobals .local/share/RecentDocuments .config/libreoffice/4/user/registrymodifications.xcu .local/share/gvfs-metadata .config/dconf/user .xsession-errors .xsession-errors.old .local/share/xorg .config/Slack/logs .config/Signal/logs .local/share/TelegramDesktop/tdata/settingss .config/discord/Local\ Storage .config/Microsoft/Microsoft\ Teams/logs.txt .thunderbird; do
      [ -e "$h/$f" ] && echo "$h/$f"; done
  done > "$C0F_TMP/desk"
  [ -s "$C0F_TMP/desk" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT" -e "$C0F_EXCL" -R -L "$C0F_TMP/desk" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
