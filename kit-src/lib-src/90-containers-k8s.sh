# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D18 / D19 =======================
container_runtime_detect() {
  for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock /var/run/crio/crio.sock /run/podman/podman.sock /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket /var/lib/incus/unix.socket; do
    [ -S "$s" ] && echo "socket: $s"; done
  for u in /run/user/*/podman/podman.sock /run/user/*/docker.sock; do [ -S "$u" ] && echo "rootless socket: $u"; done
  for d in /var/lib/docker /var/lib/containerd /var/lib/containers /var/lib/lxc /var/lib/lxd /var/snap/lxd /var/lib/incus /var/lib/machines /var/lib/rancher; do [ -d "$d" ] && echo "data folder: $d ($(du -sh "$d" 2>/dev/null | cut -f1))"; done
  for h in $(each_home | cut -f3); do [ -d "$h/.local/share/containers" ] && echo "rootless podman storage: $h/.local/share/containers"; [ -d "$h/.local/share/docker" ] && echo "rootless docker data: $h/.local/share/docker"; done
  for c in docker podman containerd ctr crictl runc crun lxc lxd incus machinectl nerdctl; do p=$(srv_path "$c") && echo "server binary: $p"; done
  echo "kit clients: docker $(docker --version 2>/dev/null | head -n 1); $(ctr --version 2>/dev/null); $(crictl --version 2>/dev/null); $(runc --version 2>/dev/null | head -n 1)"
  return 0
}
# choose a working docker client: kit (with API downgrade for old daemons) or the server's docker
docker_pick() {
  DK=docker; out=$(docker version --format '{{.Server.APIVersion}}' 2>&1); rc=$?
  if [ $rc != 0 ]; then
    v=$(printf '%s' "$out" | sed -n 's/.*[Mm]aximum supported API version is \([0-9.]*\).*/\1/p')
    if [ -n "$v" ]; then export DOCKER_API_VERSION=$v; docker version >/dev/null 2>&1 && { echo "kit docker with DOCKER_API_VERSION=$v (old daemon)"; return 0; }; fi
    if has docker; then DK="srv docker"; echo "kit docker failed ($out); using the server's docker"; return 0; fi
    echo "docker daemon not reachable: $out"; return 1
  fi
  echo "kit docker client, daemon API $out"; return 0
}
dk() { $DK "$@"; }
docker_collect() {
  docker_pick > "$ITEM_OUT/client-choice.txt" 2>&1 || { cat "$ITEM_OUT/client-choice.txt"; return 13; }
  dk version > "$ITEM_OUT/version.txt" 2>&1; dk info > "$ITEM_OUT/info.txt" 2>&1
  dk ps -a --no-trunc --size > "$ITEM_OUT/ps-a.txt" 2>&1
  dk images -a --digests --no-trunc > "$ITEM_OUT/images.txt" 2>&1
  dk network ls --no-trunc > "$ITEM_OUT/networks.txt" 2>&1; dk volume ls > "$ITEM_OUT/volumes.txt" 2>&1
  dk system df -v > "$ITEM_OUT/system-df.txt" 2>&1
  dk events --since "$(( $(date +%s) - C0F_SINCE*86400 ))" --until "$(date +%s)" > "$ITEM_OUT/events.txt" 2>&1
  mk "$ITEM_OUT/networks" "$ITEM_OUT/volumes" "$ITEM_OUT/images"
  for n in $(dk network ls -q 2>/dev/null); do dk network inspect "$n" > "$ITEM_OUT/networks/$n.json" 2>&1; done
  for v in $(dk volume ls -q 2>/dev/null); do dk volume inspect "$v" > "$ITEM_OUT/volumes/$(safe "$v").json" 2>&1; done
  for i in $(dk images -a -q --no-trunc 2>/dev/null | sort -u); do b=$(safe "${i#sha256:}" | cut -c1-20)
    dk image inspect "$i" > "$ITEM_OUT/images/$b.inspect.json" 2>&1; dk history --no-trunc "$i" > "$ITEM_OUT/images/$b.history.txt" 2>&1; done
  echo "id,name,image,image_id,created,status,started,finished,exit_code,oom_killed,restart_count,restart_policy,privileged,network_mode,pid_mode,cap_add,user,mounts,docker_sock_mounted,ips,compose_project" > "$ITEM_OUT/containers.csv"
  for c in $(dk ps -a -q --no-trunc 2>/dev/null); do
    nm=$(dk inspect --format '{{.Name}}' "$c" 2>/dev/null | tr -d '/'); d="$ITEM_OUT/containers/$(safe "$nm")_$(printf '%s' "$c" | cut -c1-12)"; mk "$d"
    dk inspect "$c" > "$d/inspect.json" 2>&1
    dk logs -t --details "$c" > "$d/logs.stdout.txt" 2> "$d/logs.stderr.txt"
    dk diff "$c" > "$d/diff.txt" 2>&1
    dk port "$c" > "$d/ports.txt" 2>&1
    if [ "$(dk inspect --format '{{.State.Running}}' "$c" 2>/dev/null)" = true ]; then dk top "$c" -eo pid,ppid,user,lstart,args > "$d/top.txt" 2>&1; dk stats --no-stream "$c" > "$d/stats.txt" 2>&1; fi
    jq -r '.[0] | [(.Id[0:12]), (.Name|ltrimstr("/")), .Config.Image, .Image, .Created, .State.Status, .State.StartedAt, .State.FinishedAt, .State.ExitCode, .State.OOMKilled, .RestartCount, .HostConfig.RestartPolicy.Name, .HostConfig.Privileged, .HostConfig.NetworkMode, .HostConfig.PidMode, ((.HostConfig.CapAdd // []) | join(" ")), .Config.User, ([.Mounts[]? | (.Source + ":" + .Destination)] | join(" ")), ([.Mounts[]? | select(.Source|test("docker.sock"))] | length > 0), ([.NetworkSettings.Networks[]? | .IPAddress] | join(" ")), (.Config.Labels["com.docker.compose.project"] // "")] | @csv' "$d/inspect.json" >> "$ITEM_OUT/containers.csv" 2>/dev/null
    cf=$(jq -r '.[0].Config.Labels["com.docker.compose.project.config_files"] // empty' "$d/inspect.json" 2>/dev/null); wd=$(jq -r '.[0].Config.Labels["com.docker.compose.project.working_dir"] // empty' "$d/inspect.json" 2>/dev/null)
    if [ -n "$cf$wd" ]; then printf '%s\n' $(printf '%s' "$cf" | tr ',' ' ') "$wd/.env" | while read -r f; do [ -f "$f" ] && echo "$f"; done > "$C0F_TMP/compose.list"
      [ -s "$C0F_TMP/compose.list" ] && c0f-copy -M "$ITEM_META" -o "$d/compose" -e "$C0F_EXCL" -L "$C0F_TMP/compose.list" 2>>"$C0F_TMP/copy-stderr.log"; fi
    rm_empty "$d"
  done
  rm_empty "$ITEM_OUT"; return 0
}
# one representative PID per container: lowest PID of every non-host PID namespace that belongs to a container cgroup
container_init_pids() {
  hostns=$(readlink /proc/1/ns/pid)
  for p in /proc/[0-9]*; do n=$(readlink "$p/ns/pid" 2>/dev/null) || continue; [ "$n" = "$hostns" ] && continue
    cg=$(tail -n 1 "$p/cgroup" 2>/dev/null); id=$(printf '%s' "$cg" | grep -oE '[0-9a-f]{64}' | tail -n 1)
    printf '%s\t%s\t%s\t%s\n' "$n" "${p##*/}" "${id:-$(safe "$cg")}" "$(cat "$p/comm" 2>/dev/null)"
  done | sort -t "$TAB" -k1,1 -k2,2n | awk -F'\t' '!s[$1]++'
}
container_namespaces() {
  container_init_pids > "$ITEM_OUT/containers-by-pid-namespace.tsv"
  [ -s "$ITEM_OUT/containers-by-pid-namespace.tsv" ] || { rm -f "${ITEM_OUT:?}/containers-by-pid-namespace.tsv"; echo "no running container"; return 10; }
  while IFS="$TAB" read -r ns pid id comm; do
    nm=$(docker ps -a --no-trunc --format '{{.ID}} {{.Names}}' 2>/dev/null | awk -v i="$id" '$1==i{print $2}')
    d="$ITEM_OUT/$(safe "${nm:-$comm}")_$(printf '%s' "$id" | cut -c1-12)_pid$pid"; mk "$d/network"
    for c in "ip -d addr" "ip route show table all" "ip neigh" "ip rule"; do nsenter -t "$pid" -n $c > "$d/network/$(safe "$c").txt" 2>&1; done
    nsenter -t "$pid" -n ss -tunap > "$d/network/ss-tunap.txt" 2>&1
    nsenter -t "$pid" -n xtables-nft-multi iptables-save -c > "$d/network/iptables-nft.txt" 2>&1
    nsenter -t "$pid" -n xtables-legacy-multi iptables-save -c > "$d/network/iptables-legacy.txt" 2>&1
    nsenter -t "$pid" -n nft list ruleset > "$d/network/nft.txt" 2>&1
    cat "/proc/$pid/net/tcp" "/proc/$pid/net/tcp6" > "$d/network/proc-net-tcp.txt" 2>/dev/null
    r="/proc/$pid/root"
    for f in etc/passwd etc/shadow etc/group etc/hosts etc/resolv.conf etc/hostname etc/os-release etc/crontab etc/cron.d var/spool/cron root/.bash_history root/.ash_history root/.sh_history root/.zsh_history root/.ssh etc/ssh/sshd_config etc/ld.so.preload etc/profile etc/rc.local; do [ -e "$r/$f" ] && echo "$r/$f"; done > "$C0F_TMP/cin.list"
    for h in "$r"/home/*; do for f in .bash_history .ash_history .sh_history .zsh_history .ssh; do [ -e "$h/$f" ] && echo "$h/$f"; done; done >> "$C0F_TMP/cin.list"
    [ -s "$C0F_TMP/cin.list" ] && c0f-copy -M "$ITEM_META" -o "$d/files" -e "$C0F_EXCL" -R -L "$C0F_TMP/cin.list" 2>>"$C0F_TMP/copy-stderr.log"
    { ls -la --time-style=full-iso "$r/tmp" "$r/var/tmp" "$r/dev/shm" 2>&1; } > "$d/temp-folders.txt"
    tr '\0' '\n' 2>/dev/null < "/proc/$pid/environ" > "$d/init-environ.txt" 2>/dev/null
    rm_empty "$d/network"; rm_empty "$d"
  done < "$ITEM_OUT/containers-by-pid-namespace.tsv"
  return 0
}
compose_dockerfiles_search() {
  printf 'category\tpath\tsize\tmtime\n' > "$ITEM_OUT/found.tsv"; : > "$C0F_TMP/build.list"
  local_fs | cut -f1 | sort -u | while read -r m; do
    find "$m" -xdev \( -path /proc -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/containerd -o -path "$C0F_EXCL" -o -path "$C0F_KITDIR" -o -name node_modules -o -name .git \) -prune -o -type f \( -name 'Dockerfile*' -o -name 'Containerfile*' -o -name '*.dockerfile' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose.yml' -o -name 'compose.yaml' -o -name 'compose.*.yml' -o -name 'compose.*.yaml' -o -name '.dockerignore' -o -name 'podman-compose*' -o -name 'Chart.yaml' -o -name 'kustomization.yaml' -o -name 'kustomization.yml' -o -name 'docker-stack*.yml' \) -print 2>/dev/null
  done | sort -u > "$C0F_TMP/build.found"
  find /etc /opt /srv /home /root /var/www /usr/local -xdev -type f \( -name '*.yaml' -o -name '*.yml' \) -size -2M 2>/dev/null | head -n 20000 | while read -r y; do grep -qE '^apiVersion:' "$y" 2>/dev/null && grep -qE '^kind:' "$y" 2>/dev/null && echo "$y"; done >> "$C0F_TMP/build.found"
  while read -r f; do b=${f##*/}
    case "$b" in Dockerfile*|Containerfile*|*.dockerfile) c=dockerfile;; docker-compose*|compose*|podman-compose*|docker-stack*) c=compose;; .dockerignore) c=dockerignore;; Chart.yaml) c=helm;; kustomization.*) c=kustomize;; *) c=kubernetes-manifest;; esac
    printf '%s\t%s\t%s\t%s\n' "$c" "$f" "$(stat -c %s "$f")" "$(stat -c %y "$f")" >> "$ITEM_OUT/found.tsv"; echo "$f"
    [ "$c" = compose ] && for e in "${f%/*}/.env" "${f%/*}"/*.env; do [ -f "$e" ] && echo "$e"; done
  done < "$C0F_TMP/build.found" | sort -u > "$C0F_TMP/build.list"
  for c in dockerfile compose dockerignore helm kustomize kubernetes-manifest; do grep -q "^$c$TAB" "$ITEM_OUT/found.tsv" && sub OK - "$c" || sub "NOT FOUND" NOT_FOUND "$c"; done
  [ -s "$C0F_TMP/build.list" ] || return 10
  c0f-copy -M "$ITEM_META" -o "$ITEM_OUT/files" -e "$C0F_EXCL" -L "$C0F_TMP/build.list" 2>>"$C0F_TMP/copy-stderr.log"; return 0
}
podman_collect() {
  if has podman; then
    srv podman version > "$ITEM_OUT/version.txt" 2>&1; srv podman ps -a --size --no-trunc > "$ITEM_OUT/ps-a.txt" 2>&1; srv podman images -a --digests > "$ITEM_OUT/images.txt" 2>&1
    srv podman pod ps > "$ITEM_OUT/pods.txt" 2>&1; srv podman volume ls > "$ITEM_OUT/volumes.txt" 2>&1; srv podman network ls > "$ITEM_OUT/networks.txt" 2>&1
    for c in $(srv podman ps -a -q --no-trunc 2>/dev/null); do d="$ITEM_OUT/root/$(printf '%s' "$c" | cut -c1-12)"; mk "$d"
      srv podman inspect "$c" > "$d/inspect.json" 2>&1; srv podman logs -t "$c" > "$d/logs.txt" 2>&1; srv podman diff "$c" > "$d/diff.txt" 2>&1; done
  fi
  for h in /var/lib/containers/storage $(each_home | cut -f3 | sed 's|$|/.local/share/containers/storage|'); do [ -d "$h" ] || continue
    cpo "$ITEM_OUT/storage-metadata" "$h/overlay-containers/containers.json" "$h/overlay-containers/volatile-containers.json" "$h/overlay-images/images.json" "$h/libpod/bolt_state.db" "$h/db.sql" "$h/overlay-containers"/*/userdata/config.json
  done
  for h in $(each_home | cut -f3); do [ -d "$h/.config/containers" ] && cpo "$ITEM_OUT/user-config" -R "$h/.config/containers"; done
  rm_empty "$ITEM_OUT"; return 0
}
containerd_cri_collect() {
  for s in /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock; do [ -S "$s" ] || continue
    d="$ITEM_OUT/containerd_$(safe "$s")"; mk "$d"
    ctr --address "$s" version > "$d/version.txt" 2>&1
    for ns in $(ctr --address "$s" namespaces ls -q 2>/dev/null); do o="$d/ns_$(safe "$ns")"; mk "$o"
      ctr --address "$s" -n "$ns" containers ls > "$o/containers.txt" 2>&1; ctr --address "$s" -n "$ns" tasks ls > "$o/tasks.txt" 2>&1
      ctr --address "$s" -n "$ns" images ls > "$o/images.txt" 2>&1; ctr --address "$s" -n "$ns" snapshots ls > "$o/snapshots.txt" 2>&1
      for c in $(ctr --address "$s" -n "$ns" containers ls -q 2>/dev/null); do ctr --address "$s" -n "$ns" containers info "$c" > "$o/container_$(safe "$c").json" 2>&1; done
    done
  done
  if command -v crictl >/dev/null 2>&1; then
    for s in /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock /var/run/crio/crio.sock; do [ -S "$s" ] || continue
      o="$ITEM_OUT/cri_$(safe "$s")"; mk "$o/logs"; ep="unix://$s"
      crictl -r "$ep" version > "$o/version.txt" 2>&1; crictl -r "$ep" ps -a > "$o/ps-a.txt" 2>&1; crictl -r "$ep" pods > "$o/pods.txt" 2>&1
      crictl -r "$ep" images > "$o/images.txt" 2>&1; crictl -r "$ep" info > "$o/info.json" 2>&1
      for c in $(crictl -r "$ep" ps -a -q 2>/dev/null); do crictl -r "$ep" inspect "$c" > "$o/inspect_$c.json" 2>&1; crictl -r "$ep" logs --timestamps "$c" > "$o/logs/$c.log" 2>&1; done
      for p in $(crictl -r "$ep" pods -q 2>/dev/null); do crictl -r "$ep" inspectp "$p" > "$o/inspectp_$p.json" 2>&1; done
    done
  else sub SKIPPED UNSUPPORTED_ARCH "crictl is not released for $ARCH: ctr data only"; fi
  rm_empty "$ITEM_OUT"; return 0
}
lxc_nspawn_collect() {
  has lxc && { srv lxc list --format csv > "$ITEM_OUT/lxd-list.csv" 2>&1; for c in $(srv lxc list --format csv -c n 2>/dev/null); do srv lxc info --show-log "$c" > "$ITEM_OUT/lxd-$(safe "$c")-info.txt" 2>&1; srv lxc config show --expanded "$c" > "$ITEM_OUT/lxd-$(safe "$c")-config.yaml" 2>&1; done; }
  has incus && { srv incus list --format csv > "$ITEM_OUT/incus-list.csv" 2>&1; }
  has lxc-ls && srv lxc-ls -f > "$ITEM_OUT/lxc-ls.txt" 2>&1
  [ -d /var/lib/lxc ] && cpo "$ITEM_OUT/lxc-config" /var/lib/lxc/*/config
  has machinectl && { srv machinectl list --all --no-pager > "$ITEM_OUT/machinectl.txt" 2>&1; srv machinectl list-images --no-pager >> "$ITEM_OUT/machinectl.txt" 2>&1; }
  rm_empty "$ITEM_OUT"; return 0
}
container_exports() {
  docker_pick > /dev/null 2>&1 || return 12
  n=0
  for c in $(dk ps -a -q --no-trunc 2>/dev/null); do
    nm=$(dk inspect --format '{{.Name}}' "$c" | tr -d '/'); sz=$(dk inspect --size --format '{{.SizeRootFs}}' "$c" 2>/dev/null)
    space_left_ok "$(( ${sz:-0} / 1024 ))" || { sub SKIPPED NO_SPACE "$nm"; continue; }
    if dk export -o "$ITEM_OUT/$(safe "$nm")_$(printf '%s' "$c" | cut -c1-12).tar" "$c" 2>>"$ITEM_OUT/export-errors.log"; then sub OK - "$nm"; n=$((n+1)); else sub FAILED EXIT_NONZERO "$nm"; fi
  done
  [ $n = 0 ] && return 10; return 0
}
k8s_detect() {
  echo "== flavour markers"
  for p in /etc/kubernetes /var/lib/kubelet /etc/rancher/k3s /var/lib/rancher/k3s /etc/rancher/rke2 /var/lib/rancher/rke2 /var/snap/microk8s /etc/kubernetes/manifests; do [ -e "$p" ] && echo "present: $p"; done
  for b in kubelet kubeadm k3s rke2 microk8s kubectl kind minikube; do p=$(srv_path "$b") && echo "binary: $p"; done
  ps -eo pid,args -ww | grep -E 'kubelet|kube-apiserver|etcd|k3s server|k3s agent|rke2|kube-proxy' | grep -v ' grep '
  echo "== kubeconfig files usable for cluster-level reads"
  for f in "$C0F_KUBECONFIG" /etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/snap/microk8s/current/credentials/client.config /root/.kube/config; do [ -n "$f" ] && [ -r "$f" ] && echo "$f"; done
  is_k8s_node || { echo "not a Kubernetes node"; return 0; }
  return 0
}
k8s_node_services() {
  for u in kubelet containerd crio docker k3s k3s-agent rke2-server rke2-agent snap.microk8s.daemon-kubelite kube-proxy etcd; do
    srv journalctl -u "$u" --no-pager -o short-iso-precise > "$ITEM_OUT/journal-$u.txt" 2>/dev/null; done
  for f in "$ITEM_OUT"/journal-*.txt; do grep -q '^-- No entries --' "$f" 2>/dev/null && rm -f "${f:?}"; done
  has ipvsadm && srv ipvsadm -Ln > "$ITEM_OUT/ipvsadm.txt" 2>&1
  [ -f /var/log/kubelet.log ] && echo "kubelet.log is copied with /var/log" > "$ITEM_OUT/kubelet-log-note.txt"
  rm_empty "$ITEM_OUT"; return 0
}
k8s_cluster_collect() {
  kc=""; for f in "$C0F_KUBECONFIG" /etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/snap/microk8s/current/credentials/client.config /root/.kube/config; do [ -n "$f" ] && [ -r "$f" ] && { kc=$f; break; }; done
  [ -n "$kc" ] || return 12
  K="kubectl --kubeconfig $kc --request-timeout=60s"
  $K version > "$ITEM_OUT/version.txt" 2>&1 || { has kubectl && K="srv kubectl --kubeconfig $kc --request-timeout=60s"; echo "kit kubectl failed, using server kubectl" >> "$ITEM_OUT/version.txt"; }
  echo "kubeconfig used: $kc" > "$ITEM_OUT/kubeconfig-used.txt"
  for r in nodes namespaces "all" events ingresses networkpolicies persistentvolumes persistentvolumeclaims storageclasses serviceaccounts roles rolebindings clusterroles clusterrolebindings mutatingwebhookconfigurations validatingwebhookconfigurations customresourcedefinitions configmaps secrets podsecuritypolicies; do
    case "$r" in nodes|namespaces|persistentvolumes|storageclasses|clusterroles|clusterrolebindings|mutatingwebhookconfigurations|validatingwebhookconfigurations|customresourcedefinitions|podsecuritypolicies) $K get "$r" -o yaml > "$ITEM_OUT/$r.yaml" 2>&1;;
      *) $K get "$r" -A -o yaml > "$ITEM_OUT/$r.yaml" 2>&1;; esac
  done
  $K get pods -A -o wide > "$ITEM_OUT/pods-wide.txt" 2>&1; $K get events -A --sort-by=.lastTimestamp > "$ITEM_OUT/events-sorted.txt" 2>&1
  mk "$ITEM_OUT/logs"
  $K get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.containers[*]}{.name}{","}{end}{range .spec.initContainers[*]}{.name}{","}{end}{"\n"}{end}' 2>/dev/null | while read -r ns pod cs; do
    for c in $(printf '%s' "$cs" | tr ',' ' '); do o="$ITEM_OUT/logs/$(safe "$ns")/$(safe "$pod")"; mk "$o"
      $K logs -n "$ns" "$pod" -c "$c" --timestamps > "$o/$(safe "$c").log" 2>&1
      $K logs -n "$ns" "$pod" -c "$c" --timestamps --previous > "$o/$(safe "$c").previous.log" 2>/dev/null || rm -f "${o:?}/$(safe "$c").previous.log"
    done
  done
  return 0
}
