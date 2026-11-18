#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# Functional tests for the C0F helpers. Run as root. usage: test-helpers.sh BINDIR FIXTURES WORKDIR [EMULATOR]
B=$1; F=$2; W=$3; E=$4; pass=0; fail=0
ok(){ pass=$((pass+1)); echo "PASS $*"; }; ko(){ fail=$((fail+1)); echo "FAIL $*"; }
chk(){ if eval "$2"; then ok "$1"; else ko "$1"; fi; }
col(){ awk -F'\t' -v s="$1" -v c="$2" '$2==s{print $c; exit}' $W/meta.tsv; }
rm -rf $W; mkdir -p $W/src/d/sub; cd $W || exit 9
for h in c0f-copy c0f-logins c0f-memdump c0f-sshkey c0f-x11; do chk "$h -V" "$E $B/$h -V | grep -q 'C0F helper'"; done
# ---------------- c0f-copy ----------------
S=$W/src/d
echo hello > $S/a.txt; echo ctl > $S/c.txt; : > $S/empty; ln -s a.txt $S/link; mkfifo $S/fifo; printf x > "$S/we:ird?name"; echo deep > $S/sub/b.txt
head -c 3000000 /dev/urandom > $S/big.bin
dd if=/dev/urandom of=$S/sparse bs=4096 count=3 seek=50000 2>/dev/null; printf START | dd of=$S/sparse conv=notrunc 2>/dev/null
touch -m -d '2001-02-03 04:05:06' $S/a.txt; touch -a -d '2000-01-01 00:00:00' $S/a.txt $S/c.txt
A0=$(stat -c %X $S/a.txt); C0=$(stat -c %X $S/c.txt)
$E $B/c0f-copy -R -M $W/meta.tsv -o $W/out $S /proc/self/status 2>$W/copy.err; echo "copy rc=$?" >> $W/copy.err
cat $S/c.txt >/dev/null
chk "control: plain read changes atime on this FS" "[ $(stat -c %X $S/c.txt) != $C0 ]"
chk "copy keeps source atime (O_NOATIME)" "[ $(stat -c %X $S/a.txt) = $A0 ]"
chk "copy content a.txt" "cmp -s $S/a.txt $W/out$S/a.txt"
chk "copy sha256 a.txt" "[ \"$(col $S/a.txt 19)\" = $(sha256sum $S/a.txt | cut -c1-64) ]"
chk "copy dest mtime = source mtime" "[ $(stat -c %Y $W/out$S/a.txt) = $(stat -c %Y $S/a.txt) ]"
chk "copy mtime recorded 2001" "col $S/a.txt 13 | grep -q '^2001-02-0'"
chk "copy noatime=yes" "[ \"$(col $S/a.txt 17)\" = yes ]"
chk "copy big content" "cmp -s $S/big.bin $W/out$S/big.bin"
chk "copy sparse content" "cmp -s $S/sparse $W/out$S/sparse"
chk "copy sparse hash = sha256sum" "[ \"$(col $S/sparse 19)\" = $(sha256sum $S/sparse | cut -c1-64) ]"
chk "copy sparse dest stays sparse" "[ $(stat -c %b $W/out$S/sparse) -lt 2000 ]"
chk "copy symlink recorded, not created" "[ \"$(col $S/link 16)\" = a.txt ] && [ ! -e $W/out$S/link ] && [ ! -L $W/out$S/link ]"
chk "copy fifo skipped" "[ \"$(col $S/fifo 1)\" = SKIPPED_SPECIAL ]"
chk "copy empty file status" "[ \"$(col $S/empty 1)\" = EMPTY ] && [ -f $W/out$S/empty ]"
chk "copy odd file name" "[ -f \"$W/out$S/we:ird?name\" ]"
chk "copy subdir" "cmp -s $S/sub/b.txt $W/out$S/sub/b.txt"
chk "copy /proc pseudo file" "[ \"$(col /proc/self/status 1)\" = OK ] && grep -q '^Name:' $W/out/proc/self/status"
chk "copy rc=0" "grep -q 'copy rc=0' $W/copy.err"
$E $B/c0f-copy -n -R $S > $W/meta-n.tsv 2>/dev/null
chk "copy -n metadata only" "[ $(wc -l < $W/meta-n.tsv) -ge 11 ] && ! grep -q 'out' $W/meta-n.tsv"
$E $B/c0f-copy -R -e $S/sub -M $W/meta-e.tsv -o $W/out3 $S 2>/dev/null
chk "copy -e exclude" "grep -q '^SKIPPED_EXCLUDED	$S/sub' $W/meta-e.tsv && [ ! -e $W/out3$S/sub/b.txt ]"
( ulimit -f 2048; $E $B/c0f-copy -M $W/meta-s.tsv -o $W/out4 $S/big.bin 2>/dev/null )
chk "copy split on EFBIG" "[ -f $W/out4$S/big.bin.c0f-part002 ] && cat $W/out4$S/big.bin $W/out4$S/big.bin.c0f-part* | cmp -s - $S/big.bin"
ln -s big.bin $S/biglink; $E $B/c0f-copy -F -M $W/meta-f.tsv -o $W/out5 $S/biglink 2>/dev/null
chk "copy -F follows top-level symlink" "cmp -s $W/out5$S/biglink $S/big.bin"
head -c 400000000 /dev/zero | tr '\0' 'a' > $W/grow.bin
( sleep 0.3; echo appended >> $W/grow.bin ) & $E $B/c0f-copy -M $W/meta-g.tsv -o $W/out6 $W/grow.bin 2>/dev/null; wait
chk "copy detects change during copy" "grep -q '^CHANGED_DURING_COPY' $W/meta-g.tsv"
rm -f $W/grow.bin; rm -rf $W/out6
# ---------------- c0f-logins ----------------
$E $B/c0f-logins utmp $F/logs/wtmp > $W/wtmp.tsv 2>$W/wtmp.err
N=$(( $(stat -c %s $F/logs/wtmp) / 384 ))
chk "logins utmp record count" "[ $(($(wc -l < $W/wtmp.tsv)-1)) = $N ]"
chk "logins utmp parses USER_PROCESS rows" "grep -q USER_PROCESS $W/wtmp.tsv"
cp $F/logs/wtmp $W/wtmp.z; dd if=/dev/zero of=$W/wtmp.z bs=384 seek=5 count=1 conv=notrunc 2>/dev/null
$E $B/c0f-logins utmp $W/wtmp.z > $W/wtmpz.tsv 2>/dev/null
chk "logins detects zeroed record" "awk -F'\t' '\$1==5' $W/wtmpz.tsv | grep -q ALL_ZERO_RECORD"
$E $B/c0f-logins lastlog -p $F/logs/passwd $F/logs/lastlog > $W/lastlog.tsv 2>/dev/null
chk "logins lastlog uid->name" "awk -F'\t' 'NR>1 && \$2!=\"-\" && \$3 ~ /^20/' $W/lastlog.tsv | grep -q ."
case "$(uname -m):$E" in x86_64:|*aarch64*) RS=32; FR="";; *) RS=24; FR="-r 24";; esac
head -c $((RS*2)) /dev/zero > $W/faillog
if [ $RS = 32 ]; then printf '\005\000\000\000ssh:notty\000\000\000\000\361\123\145\000\000\000\000\000\000\000\000\000\000\000\000' >> $W/faillog
else printf '\005\000\000\000ssh:notty\000\000\000\000\361\123\145\000\000\000\000' >> $W/faillog; fi
head -c $RS /dev/zero >> $W/faillog
$E $B/c0f-logins faillog $FR $W/faillog > $W/faillog.tsv 2>/dev/null
chk "logins faillog record" "grep -q '	5	0	2023-11-14T22:13:20Z	ssh:notty' $W/faillog.tsv"
# ---------------- c0f-memdump ----------------
env C0F_TEST_MARK=C0F-MEMDUMP-MARKER-31337 sleep 60 & P=$!; sleep 0.5
$E $B/c0f-memdump $P $W/md 2>$W/md.err; echo "rc=$?" >> $W/md.err
chk "memdump marker found in .mem" "grep -ac 'C0F-MEMDUMP-MARKER-31337' $W/md.mem | grep -qv '^0$'"
chk "memdump regions.tsv stack OK" "grep -q '\[stack\].*OK' $W/md.regions.tsv"
chk "memdump info + maps" "grep -q '^pid: $P' $W/md.info.txt && cat /proc/$P/maps | cmp -s - $W/md.maps"
$E $B/c0f-memdump -S $P $W/md2 2>/dev/null; ST=$(awk '{print $3}' /proc/$P/stat)
chk "memdump -S resumes process" "[ \"$ST\" != T ] && grep -q 'stopped_during_dump: yes' $W/md2.info.txt"
kill $P 2>/dev/null
# ---------------- c0f-sshkey ----------------
$E $B/c0f-sshkey $F/ssh/* > $W/ssh.tsv 2>$W/ssh.err
while read k bits fs fm; do [ -z "$k" ] && continue
  case $k in id_ecdsa_pem_enc|id_rsa_pkcs8_enc) chk "sshkey $k.pub fp" "grep -q \"$fs	$fm\" $W/ssh.tsv";;
    *) chk "sshkey $k private fp+md5" "awk -F'\t' -v f=\"$F/ssh/$k\" '\$1==f' $W/ssh.tsv | grep -q \"$fs	$fm\"";; esac
done < $F/expected-fp.txt
chk "sshkey ed25519 comment + no passphrase" "awk -F'\t' -v f=$F/ssh/id_ed25519 '\$1==f' $W/ssh.tsv | grep -q 'NO PASSPHRASE.*alice@host1'"
chk "sshkey encrypted openssh" "awk -F'\t' -v f=$F/ssh/id_rsa_enc '\$1==f{print \$8,\$9,\$10,\$11}' $W/ssh.tsv | grep -q '^yes aes256-ctr bcrypt [0-9]'"
chk "sshkey encrypted PEM" "awk -F'\t' -v f=$F/ssh/id_ecdsa_pem_enc '\$1==f{print \$3,\$8}' $W/ssh.tsv | grep -q '^pem-private yes'"
chk "sshkey encrypted PKCS8" "awk -F'\t' -v f=$F/ssh/id_rsa_pkcs8_enc '\$1==f{print \$3}' $W/ssh.tsv | grep -q pkcs8-encrypted"
chk "sshkey putty ppk" "grep -q 'putty-private	ssh-ed25519	256	SHA256:QfipqiQ4Tt3pkN0NoeXFGi8tQlUI4JzJHhOV9vgtXu4' $W/ssh.tsv"
chk "sshkey authorized_keys options" "grep -q 'option command=; option from=' $W/ssh.tsv"
chk "sshkey known_hosts hashed" "[ $(grep -c 'hashed hostname' $W/ssh.tsv) -ge 2 ]"
chk "sshkey garbage line flagged" "grep -q 'unrecognised line' $W/ssh.tsv"
chk "sshkey never prints private base64" "! grep -q 'BEGIN\|PRIVATE KEY-----' $W/ssh.tsv"
echo "RESULT pass=$pass fail=$fail"
