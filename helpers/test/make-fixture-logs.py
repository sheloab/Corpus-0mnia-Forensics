#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
"""Write SYNTHETIC login records for the c0f-logins tests (no real data):
   wtmp    glibc on-disk layout, 384-byte records (x86_64/aarch64/armv7 glibc all use 32-bit time fields)
   lastlog glibc layout, 292-byte records indexed by uid
   passwd  matching accounts
Users and addresses are fictional (RFC 5737 / RFC 3849 documentation ranges).
usage: make-fixture-logs.py OUTDIR"""
import os, socket, struct, sys

out = sys.argv[1] if len(sys.argv) > 1 else "fixtures/logs"
os.makedirs(out, exist_ok=True)
BOOT, LOGIN, USER, DEAD = 2, 6, 7, 8
T0 = 1793500000  # 2026-10-31 UTC

def addr(ip):
    if not ip:
        return (0, 0, 0, 0)
    if ":" in ip:
        return struct.unpack("<4i", socket.inet_pton(socket.AF_INET6, ip))
    return (struct.unpack("<i", socket.inet_aton(ip))[0], 0, 0, 0)

def utmp(typ, pid, line, uid, user, host, t, ip=""):
    rec = struct.pack("<hhi32s4s32s256shhiii4i20s", typ, 0, pid, line.encode(), uid.encode(), user.encode(),
                      host.encode(), 0, 0, 0, t, 0, *addr(ip), b"")
    assert len(rec) == 384
    return rec

recs = [utmp(BOOT, 0, "~", "~~", "reboot", "6.1.0-test", T0), utmp(LOGIN, 700, "tty1", "tty1", "LOGIN", "", T0 + 30)]
logins = [("alice", "192.0.2.10"), ("bob", "198.51.100.7"), ("alice", "2001:db8::25"), ("root", "203.0.113.99"),
          ("bob", "192.0.2.44"), ("alice", "198.51.100.200")]
pid = 1000
for i, (u, ip) in enumerate(logins):
    t = T0 + 600 * (i + 1); pid += 37; line = "pts/%d" % (i % 4)
    recs.append(utmp(USER, pid, line, "ts/%d" % (i % 4), u, ip, t, ip))
    recs.append(utmp(DEAD, pid, line, "ts/%d" % (i % 4), "", "", t + 300))
with open(os.path.join(out, "wtmp"), "wb") as f:
    f.write(b"".join(recs))

accounts = [("root", 0), ("daemon", 1), ("alice", 1000), ("bob", 1001)]
ll = bytearray(292 * 1002)
for name, uid, t, line, host in [("root", 0, T0 + 2400, "pts/3", "203.0.113.99"),
                                 ("alice", 1000, T0 + 3600, "pts/1", "198.51.100.200"),
                                 ("bob", 1001, T0 + 3000, "pts/0", "192.0.2.44")]:
    ll[292 * uid:292 * (uid + 1)] = struct.pack("<i32s256s", t, line.encode(), host.encode())
with open(os.path.join(out, "lastlog"), "wb") as f:
    f.write(bytes(ll))

with open(os.path.join(out, "passwd"), "w") as f:
    for name, uid in accounts:
        home = "/root" if uid == 0 else ("/usr/sbin" if uid == 1 else "/home/" + name)
        shell = "/usr/sbin/nologin" if uid == 1 else "/bin/bash"
        f.write("%s:x:%d:%d::%s:%s\n" % (name, uid, uid, home, shell))
print("wrote", out, len(recs), "wtmp records")
