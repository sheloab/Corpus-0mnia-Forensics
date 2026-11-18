# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Third-party components of the kit (name, version, files in bin/, license, source, how verified). Shared by
gen_readme.py and gen_reference.py."""

def components(V):
    return [
 ("BusyBox", "1.38.0 + 1 C0F patch (build/patches: ash read after a trapped signal)", "busybox (shell for c0f.sh + applets: awk, sed, grep, netstat, lsmod, ...)", "GPL-2.0", "https://busybox.net/downloads/", "GPG signature"),
     ("GNU coreutils", "9.12", "ls, stat, sha256sum, md5sum, date, timeout, cp, dd, sort, ...", "GPL-3.0+", "https://ftp.gnu.org/gnu/coreutils/", "GPG signature"),
     ("GNU findutils", "4.11.0", "find, xargs", "GPL-3.0+", "https://ftp.gnu.org/gnu/findutils/", "GPG signature"),
     ("GNU tar", "1.35", "tar", "GPL-3.0+", "https://ftp.gnu.org/gnu/tar/", "GPG signature"),
     ("util-linux", "2.42.4", "lsblk, findmnt, blkid, fdisk, sfdisk, lsns, nsenter, lslocks, lsipc, dmesg, lslogins, lastlog2, hwclock, script, flock, setsid, ionice, blockdev, wipefs", "GPL-2.0+ and others", "https://www.kernel.org/pub/linux/utils/util-linux/", "kernel.org signature"),
     ("iproute2", "7.3.0", "ip, ss, bridge", "GPL-2.0", "https://www.kernel.org/pub/linux/utils/net/iproute2/", "kernel.org signature"),
     ("e2fsprogs", "1.47.4", "debugfs, e2image, tune2fs, dumpe2fs, lsattr", "GPL-2.0", "https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/", "kernel.org signature"),
     ("acl / attr", "2.4.0 / 2.6.0", "getfacl / getfattr", "GPL-2.0+, LGPL-2.1+", "https://download.savannah.nongnu.org/releases/", "GPG signature"),
     ("libcap", "2.78", "getcap", "BSD-3-Clause or GPL-2.0", "https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/", "kernel.org signature"),
     ("iptables (+libmnl, libnftnl)", "1.8.13", "xtables-legacy-multi, xtables-nft-multi (iptables/ip6tables/arptables/ebtables save)", "GPL-2.0", "https://www.netfilter.org/projects/", "GPG signature"),
     ("nftables", "1.1.7", "nft", "GPL-2.0", "https://www.netfilter.org/projects/nftables/", "GPG signature"),
     ("ipset", "7.24", "ipset", "GPL-2.0", "https://ipset.netfilter.org/", "SHA-512 (no signature published)"),
     ("libpcap / tcpdump", "1.11.0 / 4.99.7", "tcpdump", "BSD-3-Clause", "https://www.tcpdump.org/release/", "GPG signature"),
     ("procps-ng", "4.0.7", "ps, pgrep, pkill, pmap, free, uptime, vmstat, sysctl, pwdx", "GPL-2.0+, LGPL-2.1+", "https://gitlab.com/procps-ng/procps (tag v4.0.7)", "tag archive (no signature published)"),
     ("lsof", "4.99.7", "lsof", "lsof license (BSD-like)", "https://github.com/lsof-org/lsof/releases", "release digest"),
     ("dmidecode", "3.7", "dmidecode", "GPL-2.0+", "https://download.savannah.gnu.org/releases/dmidecode/", "GPG signature"),
     ("file", "5.48", "file + share/magic.mgc", "BSD-2-Clause", "https://astron.com/pub/file/", "GPG signature"),
     ("SQLite", "3.54.0", "sqlite3", "Public domain", "https://sqlite.org/", "SHA3-256 published on sqlite.org"),
     ("libsodium / minisign", "1.0.22 / 0.12", "minisign (kit signature check)", "ISC", "https://download.libsodium.org/ , https://github.com/jedisct1/minisign", "minisign signatures"),
     ("chkrootkit", "0.58b + Debian 0.58b-5 patches", "chkrootkit/ (script + chkproc, chkdirs, ifpromisc, chkutmp, chkwtmp, chklastlog, strings-static)", "BSD-2-Clause", "https://deb.debian.org/debian/pool/main/c/chkrootkit/", "Debian archive signature chain"),
     ("C0F helpers", V, "c0f-copy, c0f-logins, c0f-memdump, c0f-sshkey, c0f-x11", "MIT OR GPL-2.0-or-later (dual; LICENSES/C0F.txt)", "built from the C0F source", "-"),
     ("docker CLI / containerd ctr / runc", "29.9.3 / 2.4.2 / 1.5.2", "docker, ctr, runc", "Apache-2.0", "https://download.docker.com/linux/static/stable/", "SHA-256 recorded at download"),
     ("kubectl", "1.37.2", "kubectl", "Apache-2.0", "https://dl.k8s.io/release/", "published SHA-256"),
     ("crictl", "1.37.0", "crictl (x86_64, aarch64 only)", "Apache-2.0", "https://github.com/kubernetes-sigs/cri-tools/releases", "published SHA-256"),
     ("jq", "1.8.2", "jq", "MIT", "https://github.com/jqlang/jq/releases", "published SHA-256"),
     ("AVML", "0.21.0", "avml (x86_64, aarch64 only)", "MIT", "https://github.com/microsoft/avml/releases", "release digest"),
     ("7-Zip", "26.05", "7zzs", "LGPL-2.1 + unRAR restriction", "https://www.7-zip.org/", "SHA-256 recorded at download"),
    ]
