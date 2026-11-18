#!/bin/bash
# Record every demo input from one kit: interactive run, abort, Ctrl+C, unattended run, --help, error cases.
# usage: record-all.sh KITDIR OUTDIR      (OUTDIR is emptied first; throw-away containers, hostname demo-server)
set -u
K=$(cd "${1:?kit}" && pwd); O=${2:?outdir}; D=$(cd "$(dirname "$0")" && pwd); B=$(cd "$D/.." && pwd)
IMG=debian:trixie-slim
rm -rf "${O:?}"; mkdir -p "$O/err" "$O/ev"; O=$(cd "$O" && pwd)
# modified kit copies for the integrity cases (hardlinks; the changed file is a new real file)
TQ=$B/tmp-recq; TC=$B/tmp-recc
rm -rf "${B:?}/tmp-recq" "${B:?}/tmp-recc"; cp -al "$K" "$TQ"; cp -al "$K" "$TC"
rm "$TQ/bin/x86_64/lsns"; cp "$K/bin/x86_64/lsns" "$TQ/bin/x86_64/lsns"; printf 'X' >> "$TQ/bin/x86_64/lsns"
rm "$TC/c0f.sh"; cp "$K/c0f.sh" "$TC/c0f.sh"; echo '# changed' >> "$TC/c0f.sh"

rec() { # name feed-mode kit command   (interactive, through a pty)
  : > "$O/$1.raw"
  script -q -f -E always --log-out "$O/$1.raw" --log-timing "$O/$1.tim" \
    -c "stty cols 110 rows 36; sudo -n docker run --rm -it --name c0f-rec-$1 --hostname demo-server -e TERM=xterm-256color -v $3:/kit:ro -v $O/ev/$1:/evidence $IMG sh -c '$4; echo \"[exit code: \$?]\"'" < <(bash "$D/feed-all.sh" "$O/$1.raw" "$2") >/dev/null 2>&1
  pkill -f '[f]eed-all\.sh' 2>/dev/null; return 0
}
run() { # name kit extra-docker-args command   (no terminal)
  { echo "### $1"; echo "\$ $4"; } > "$O/err/$1.txt"
  sudo -n docker run --rm --hostname demo-server -v "$2":/kit:ro $3 $IMG sh -c "$4; echo \"[exit code: \$?]\"" >> "$O/err/$1.txt" 2>&1
}
for n in demo abort ctrlc yes; do sudo -n install -d -m 777 "$O/ev/$n"; done
rec demo  demo  "$K" '/kit/c0f --out /evidence --no-ram --pcap-seconds 5'
rec abort abort "$K" '/kit/c0f --out /evidence --no-ram --pcap-seconds 5'
rec ctrlc ctrlc "$K" '/kit/c0f --out /evidence --no-ram --pcap-seconds 5'
rec yes   none  "$K" '/kit/c0f --yes --case IR-2026-0042 --examiner J.Analyst --out /evidence --no-ram --pcap-seconds 5'
for n in abort ctrlc yes; do mv "$O/$n.raw" "$O/int-$n.raw" 2>/dev/null; done; mv "$O/int-yes.raw" "$O/yes-run.raw"
sudo -n docker run --rm -v "$K":/kit:ro $IMG /kit/c0f --help > "$O/help.txt" 2>&1
run 01-unknown-option "$K" "" "/kit/c0f --fast"
run 02-pcap-seconds   "$K" "" "/kit/c0f --pcap-seconds abc"
run 03-timeout-factor "$K" "" "/kit/c0f --timeout-factor 0"
run 04-since          "$K" "" "/kit/c0f --since 30days"
run 05-yes-no-case    "$K" "" "/kit/c0f --yes --out /evidence"
run 06-not-root       "$K" "--user 1000" "/kit/c0f --yes --case IR-1 --examiner J.Analyst"
run 07-tmpfs-out      "$K" "--tmpfs /ram" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /ram/ev"
run 08-readonly-out   "$K" "--read-only --tmpfs /tmp" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /mnt/ev"
run 09-lock           "$K" "" "mkdir -p /evidence && echo 1 > /evidence/.c0f.lock && /kit/c0f --yes --case IR-1 --examiner J.Analyst --out /evidence"
run 10-no-tty-no-yes  "$K" "" "/kit/c0f --out /evidence --case IR-1 --examiner J.Analyst"
run 11-core-modified  "$TC" "" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /evidence; rc=\$?; echo '--- details file:'; head -6 /evidence/C0F-KIT-VERIFY-FAILED_*.txt; exit \$rc"
run 12-force-short    "$TC" "" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /evidence --force-untrusted-kit test"
run 13-force-ok       "$TC" "" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /evidence --force-untrusted-kit 'lab test of a modified kit' --no-ram --pcap-seconds 5"
run 14-tool-modified  "$TQ" "" "/kit/c0f --yes --case IR-1 --examiner J.Analyst --out /evidence --no-ram --pcap-seconds 5"
rm -rf "${B:?}/tmp-recq" "${B:?}/tmp-recc"
sudo -n rm -rf "$O/ev"
echo "recorded into $O"
