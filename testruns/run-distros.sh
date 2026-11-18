#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Step 4 test: run the kit in throw-away containers of several distributions (no network, unprivileged).
B=$(cd "$(dirname "$0")/.." && pwd); R=$B/testruns/distro; mkdir -p "$R"; chmod 700 "$R"
SUM=$R/SUMMARY.txt; : > "$SUM"
for img in c0f-scratch:1 centos:6 centos:7 rockylinux:9 ubuntu:16.04 ubuntu:24.04 debian:8 alpine:3.20 amazonlinux:2023; do
  n=$(echo "$img" | tr ':.' '--'); o=$R/$n; mkdir -p "$o"
  case $img in c0f-scratch:1|centos:6) cmd="/kit/bin/x86_64/busybox sh /kit/c0f";; *) cmd=/kit/c0f;; esac
  t0=$(date +%s)
  sudo -n docker run --rm --name "c0f-t-$n" --network none --cap-add SYS_PTRACE --hostname "t-$n" \
    -v "$B/kit/C0F-KIT:/kit:ro" -v "$o:/out" "$img" $cmd --yes --case "DISTRO-$n" --examiner tester --out /out \
    --no-timeline --no-e2image --pcap-seconds 3 > "$o.console.txt" 2>&1
  rc=$?; t1=$(date +%s); sudo -n chown -R "$(id -u):$(id -g)" "$o"; chmod -R go-rwx "$o"
  {
    echo "=== $img  rc=$rc  $((t1-t0))s"
    grep -E "KIT INTEGRITY:|profile |COLLECTION FINISHED|Collected:|EXPECTED_BUT_MISSING|ERROR|not found|can't|cannot" "$o.console.txt" | head -12 | sed 's/^/  /'
    grep -hE "^  D[0-9]{2}-[0-9]{3} +(FAILED|TIMEOUT|DENIED|KILLED|ABANDONED)" "$o"/*.report.txt 2>/dev/null | cut -c1-170 | sed 's/^/  /'
    grep -c "CORPU5 0MNIA FORENSICS" "$o.console.txt" | sed 's/^/  closer lines: /'
  } >> "$SUM"
done
echo ALL-DONE >> "$SUM"
