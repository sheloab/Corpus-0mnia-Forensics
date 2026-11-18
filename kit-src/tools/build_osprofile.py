#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Write os-profile.tsv: what C0F expects on each OS family/version.
Columns: profile, id_regex (matched against os-release ID and every ID_LIKE word), version_min, version_max,
family, package_manager, init_default, expect_must (commands; missing = EXPECTED_BUT_MISSING warning),
expect_default (commands or /paths present on a DEFAULT install; missing = informational), notes.
The profile only sets expectations. Collection itself is capability based: every candidate location is checked."""
import sys
R = [
 ("el5", "rhel|centos|scientific|ol|oracle|cloudlinux", "5", "5.99", "rhel", "rpm", "sysvinit", "rpm yum service chkconfig", "/var/log/secure /var/log/messages /var/log/yum.log syslogd", "yum.log has no year; rpm DB is Berkeley DB (copied raw, queried with the server's rpm from a copy)"),
 ("el6", "rhel|centos|scientific|ol|oracle|cloudlinux", "6", "6.99", "rhel", "rpm", "upstart", "rpm yum service chkconfig", "/var/log/secure /var/log/messages /var/log/yum.log rsyslogd iptables", "upstart + SysV scripts; yum.log has no year"),
 ("el7", "rhel|centos|scientific|ol|oracle|cloudlinux|virtuozzo", "7", "7.99", "rhel", "rpm", "systemd", "rpm yum", "/var/log/secure /var/log/messages /var/log/yum.log rsyslogd firewall-cmd sestatus", "yum (Python 2) history in /var/lib/yum/history/*.sqlite; yum.log has no year"),
 ("amzn2", "amzn", "2", "2.99", "rhel", "rpm", "systemd", "rpm yum", "/var/log/secure /var/log/messages /var/log/yum.log rsyslogd", "Amazon Linux 2 (EL7 based)"),
 ("el8", "rhel|centos|rocky|almalinux|ol|oracle|cloudlinux|eurolinux|circle|navy", "8", "8.99", "rhel", "rpm", "systemd", "rpm dnf", "/var/log/secure /var/log/messages /var/log/dnf.log rsyslogd firewall-cmd sestatus", "yum is a link to dnf (DNF 4); history /var/lib/dnf/history.sqlite"),
 ("el9", "rhel|centos|rocky|almalinux|ol|oracle|cloudlinux|eurolinux|circle|navy", "9", "9.99", "rhel", "rpm", "systemd", "rpm dnf", "/var/log/secure /var/log/messages /var/log/dnf.log rsyslogd firewall-cmd sestatus", "DNF 4; rpm DB is sqlite (/var/lib/rpm/rpmdb.sqlite)"),
 ("el10", "rhel|centos|rocky|almalinux|ol|oracle", "10", "10.99", "rhel", "rpm", "systemd", "rpm dnf", "/var/log/dnf.log firewall-cmd sestatus", "dnf history per RHEL 10 docs; dnf4/dnf5 history locations are both checked; syslog files depend on rsyslog being installed"),
 ("amzn2023", "amzn", "2022", "2099", "rhel", "rpm", "systemd", "rpm dnf", "/var/log/dnf.log", "Amazon Linux 2023: journald only by default (no /var/log/secure)"),
 ("fedora", "fedora", "-", "-", "rhel", "rpm", "systemd", "rpm dnf", "/var/log/journal", "Fedora 41+ uses dnf5 (history under /usr/lib/sysimage/libdnf5 or /usr/lib/sysimage/dnf); journald only by default"),
 ("debian-old", "debian|raspbian", "1", "7.99", "debian", "dpkg", "sysvinit", "dpkg apt-get", "/var/log/auth.log /var/log/syslog /var/log/wtmp rsyslogd", "SysV init"),
 ("debian8-11", "debian|raspbian", "8", "11.99", "debian", "dpkg", "systemd", "dpkg apt-get", "/var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/lastlog rsyslogd", "-"),
 ("debian12", "debian|raspbian", "12", "12.99", "debian", "dpkg", "systemd", "dpkg apt-get", "/var/log/journal /var/log/wtmp", "rsyslog is no longer installed by default: auth.log/syslog exist only when rsyslog was added"),
 ("debian13+", "debian", "13", "99", "debian", "dpkg", "systemd", "dpkg apt-get", "/var/lib/wtmpdb/wtmp.db /var/lib/lastlog/lastlog2.db /var/log/journal", "wtmp/lastlog replaced by wtmpdb/lastlog2; last/utmpdump not shipped"),
 ("ubuntu-upstart", "ubuntu", "10", "15.04", "debian", "dpkg", "upstart", "dpkg apt-get", "/var/log/auth.log /var/log/syslog /var/log/wtmp rsyslogd ufw", "upstart"),
 ("ubuntu", "ubuntu", "15.10", "99", "debian", "dpkg", "systemd", "dpkg apt-get", "/var/log/auth.log /var/log/syslog /var/log/wtmp rsyslogd ufw snap", "-"),
 ("linuxmint-pop-kali", "linuxmint|pop|kali|elementary|zorin|neon|parrot|devuan|deepin|pureos", "-", "-", "debian", "dpkg", "systemd", "dpkg apt-get", "/var/log/journal", "Debian/Ubuntu derivative (Devuan uses sysvinit/openrc)"),
 ("suse", "sles|sled|opensuse|opensuse-leap|opensuse-tumbleweed|suse|opensuse-microos", "-", "-", "suse", "rpm", "systemd", "rpm zypper", "/var/log/zypp/history /var/log/journal", "rsyslog optional; zypp history logs installs and removals"),
 ("alpine", "alpine", "-", "-", "alpine", "apk", "openrc", "apk", "/var/log/messages /etc/apk/world", "BusyBox userland; apk keeps NO install/remove log"),
 ("arch", "arch|manjaro|endeavouros|garuda|artix|archarm", "-", "-", "arch", "pacman", "systemd", "pacman", "/var/log/pacman.log /var/log/journal", "pacman.log holds install/remove history"),
 ("gentoo", "gentoo|funtoo", "-", "-", "gentoo", "portage", "openrc", "emerge", "/var/log/emerge.log", "-"),
 ("void", "void", "-", "-", "void", "xbps", "runit", "xbps-query", "/var/log/socklog", "runit + socklog"),
 ("nixos", "nixos", "-", "-", "nixos", "nix", "systemd", "nix-store", "/var/log/journal", "declarative configuration in /etc/nixos"),
 ("photon-mariner-azure", "photon|mariner|azurelinux", "-", "-", "rhel", "rpm", "systemd", "rpm tdnf", "/var/log/journal", "tdnf"),
 ("busybox-embedded", "openwrt|buildroot", "-", "-", "embedded", "opkg", "procd", "-", "/var/log/messages", "embedded / router firmware"),
 ("rhel-any", "rhel|centos|rocky|almalinux|ol|oracle|amzn|cloudlinux|scientific", "-", "-", "rhel", "rpm", "systemd", "rpm", "-", "RHEL family, version not recognised"),
 ("debian-any", "debian|raspbian", "-", "-", "debian", "dpkg", "systemd", "dpkg", "-", "Debian, version not recognised (testing/sid)"),
 ("ubuntu-any", "ubuntu", "-", "-", "debian", "dpkg", "systemd", "dpkg", "-", "Ubuntu, version not recognised"),
 ("generic", ".*", "-", "-", "unknown", "unknown", "unknown", "-", "-", "no specific profile: only capability-based checks"),
]
with open(sys.argv[1], "w") as f:
    f.write("profile\tid_regex\tversion_min\tversion_max\tfamily\tpackage_manager\tinit_default\texpect_must\texpect_default\tnotes\n")
    for r in R: f.write("\t".join(r) + "\n")
print(f"os-profile: {len(R)} profiles -> {sys.argv[1]}")
