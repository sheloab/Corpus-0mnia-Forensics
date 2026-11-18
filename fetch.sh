#!/bin/sh
# Download the official sources/binaries + their signatures/checksums used for the C0F kit.
# curl reads ~/.curlrc (set a User-Agent there if your policy needs one), or set C0F_UA.
set -u
cd "$(dirname "$0")"
get(){ # url dest
  [ -s "$2" ] && { echo "have $2"; return 0; }
  if curl -fsSL ${C0F_UA:+-A "$C0F_UA"} --retry 3 --max-time 600 -o "$2.part" "$1"; then mv "$2.part" "$2"; echo "ok   $2"; else rm -f "$2.part"; echo "FAIL $1"; fi
}
s(){ get "$1" "src/$(basename "$1")"; get "$1.$2" "sig/$(basename "$1").$2"; }
# --- sources (built here) ---
s https://busybox.net/downloads/busybox-1.38.0.tar.bz2 sig
s https://ftp.gnu.org/gnu/coreutils/coreutils-9.12.tar.xz sig
s https://ftp.gnu.org/gnu/findutils/findutils-4.11.0.tar.xz sig
get https://www.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-2.42.4.tar.xz src/util-linux-2.42.4.tar.xz
get https://www.kernel.org/pub/linux/utils/util-linux/v2.42/util-linux-2.42.4.tar.sign sig/util-linux-2.42.4.tar.sign
get https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-7.3.0.tar.xz src/iproute2-7.3.0.tar.xz
get https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-7.3.0.tar.sign sig/iproute2-7.3.0.tar.sign
s https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 sig
s https://www.netfilter.org/pub/libnftnl/libnftnl-1.3.2.tar.xz sig
s https://www.netfilter.org/pub/iptables/iptables-1.8.13.tar.xz sig
s https://www.netfilter.org/pub/nftables/nftables-1.1.7.tar.xz sig
s https://www.tcpdump.org/release/libpcap-1.11.0.tar.xz sig
s https://www.tcpdump.org/release/tcpdump-4.99.7.tar.xz sig
s https://download.savannah.gnu.org/releases/dmidecode/dmidecode-3.7.tar.xz sig
s https://astron.com/pub/file/file-5.48.tar.gz asc
get https://github.com/lsof-org/lsof/releases/download/4.99.7/lsof-4.99.7.tar.gz src/lsof-4.99.7.tar.gz
get https://ftp.gnu.org/gnu/gnu-keyring.gpg sig/gnu-keyring.gpg
# --- toolchain ---
s https://ziglang.org/download/0.17.1/zig-x86_64-linux-0.17.1.tar.xz minisig
s https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux.tar.gz minisig
s https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12.tar.gz minisig
# --- official prebuilt static binaries ---
mkdir -p bin-official
for a in x86_64 aarch64 armhf; do get https://download.docker.com/linux/static/stable/$a/docker-29.9.3.tgz bin-official/docker-29.9.3-$a.tgz; done
for a in amd64 arm64 arm; do get https://dl.k8s.io/release/v1.37.2/bin/linux/$a/kubectl bin-official/kubectl-1.37.2-$a; get https://dl.k8s.io/release/v1.37.2/bin/linux/$a/kubectl.sha256 bin-official/kubectl-1.37.2-$a.sha256
  get https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.37.0/crictl-v1.37.0-linux-$a.tar.gz bin-official/crictl-v1.37.0-linux-$a.tar.gz
  get https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.37.0/crictl-v1.37.0-linux-$a.tar.gz.sha256 bin-official/crictl-v1.37.0-linux-$a.tar.gz.sha256; done
for a in amd64 arm64 armhf; do get https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-linux-$a bin-official/jq-1.8.2-linux-$a; done
get https://github.com/jqlang/jq/releases/download/jq-1.8.2/sha256sum.txt bin-official/jq-1.8.2-sha256sum.txt
for f in avml avml-aarch64 avml-armv6b; do get https://github.com/microsoft/avml/releases/download/v0.21.0/$f bin-official/avml-0.21.0-$f; done
for a in x64 arm64 arm; do get https://github.com/ip7z/7zip/releases/download/26.05/7z2605-linux-$a.tar.xz bin-official/7z2605-linux-$a.tar.xz; done
# --- more sources ---
s https://ftp.gnu.org/gnu/tar/tar-1.35.tar.xz sig
get https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.4/e2fsprogs-1.47.4.tar.xz src/e2fsprogs-1.47.4.tar.xz
get https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.4/e2fsprogs-1.47.4.tar.sign sig/e2fsprogs-1.47.4.tar.sign
s https://download.savannah.nongnu.org/releases/acl/acl-2.4.0.tar.xz sig
s https://download.savannah.nongnu.org/releases/attr/attr-2.6.0.tar.xz sig
get https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.78.tar.xz src/libcap-2.78.tar.xz
get https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.78.tar.sign sig/libcap-2.78.tar.sign
s https://www.netfilter.org/pub/ipset/ipset-7.24.tar.bz2 sig
s https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz minisig
get https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-4.0.7.tar.xz/download src/procps-ng-4.0.7.tar.xz
get https://gitlab.com/procps-ng/procps/-/archive/v4.0.7/procps-v4.0.7.tar.gz src/procps-v4.0.7-gitlab.tar.gz
get https://www.sqlite.org/2026/sqlite-autoconf-3540000.tar.gz src/sqlite-autoconf-3540000.tar.gz
get https://www.sqlite.org/releaselog/3_54_0.html sig/sqlite-3_54_0-releaselog.html
