#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors
# X11 helper test on a private Xvfb display :99 (never touches existing sessions). usage: test-x11.sh BINDIR [EMU]
B=$1; E=$2; X=/tmp/c0f-x; pass=0; fail=0
ok(){ pass=$((pass+1)); echo "PASS $*"; }; ko(){ fail=$((fail+1)); echo "FAIL $*"; }
chk(){ if eval "$2"; then ok "$1"; else ko "$1"; fi; }
rm -rf $X; mkdir -p $X; export XAUTHORITY=$X/auth DISPLAY=:99
xauth -f $X/auth add :99 MIT-MAGIC-COOKIE-1 $(od -An -tx1 -N16 /dev/urandom | tr -d ' \n') 2>/dev/null
Xvfb :99 -auth $X/auth -screen 0 800x600x24 -nolisten tcp >$X/xvfb.log 2>&1 & XP=$!; sleep 2
xterm -T C0F-TEST-WINDOW -geometry 40x10+50+60 & TP=$!; sleep 2
printf 'C0F clipboard test \303\244\303\266\303\274 line2' | xclip -selection clipboard; printf 'primary-text-123' | xclip -selection primary
sleep 1
$E $B/c0f-x11 -d :99 -a $X/auth info > $X/info.txt 2>&1
chk "x11 info size" "grep -q '^width	800' $X/info.txt && grep -q '^depth	24' $X/info.txt"
$E $B/c0f-x11 -d :99 -a $X/auth windows > $X/win.tsv 2>$X/win.err
N1=$(($(wc -l < $X/win.tsv)-1)); N2=$(xwininfo -root -tree | grep -c '^ *0x')
chk "x11 window count = xwininfo ($N1 vs root+$N2)" "[ $N1 = $((N2+1)) ]"
chk "x11 xterm window: WM_COMMAND, _NET_WM_PID and X-Resource PID" "awk -F'\t' '\$18 ~ /C0F-TEST-WINDOW/ && \$12==$TP && \$13==$TP' $X/win.tsv | grep -q ."
chk "x11 WM_CLASS" "grep -q 'xterm|XTerm' $X/win.tsv"
$E $B/c0f-x11 -d :99 -a $X/auth clipboard $X/clip > $X/clip.tsv 2>$X/clip.err
F=$(awk -F'\t' '$1=="CLIPBOARD" && $7=="UTF8_STRING"{print $12}' $X/clip.tsv)
chk "x11 clipboard UTF8 content" "[ -n \"$F\" ] && [ \"\$(cat $X/clip/$F)\" = \"\$(xclip -o -selection clipboard)\" ]"
OP=$(awk -F'\t' '$1=="CLIPBOARD"{print $3; exit}' $X/clip.tsv); XC=$(pgrep -n -f 'xclip -selection clipboard')
chk "x11 clipboard owner pid via X-Resource ($OP; xclip child $XC, parent may have exited)" "[ \"$OP\" = \"$XC\" ] || [ \"$OP\" = \"$((XC-1))\" ]"
chk "x11 primary content" "grep -l 'primary-text-123' $X/clip/PRIMARY_* >/dev/null 2>&1"
chk "x11 secondary empty" "grep -q '^SECONDARY.*NO_OWNER' $X/clip.tsv"
NOW=$(sed -n 's/.*server_time_ms=\([0-9]*\).*/\1/p' $X/clip.err); TS=$(awk -F'\t' '$1=="CLIPBOARD"{print $5; exit}' $X/clip.tsv); EST=$(awk -F'\t' '$1=="CLIPBOARD"{print $6; exit}' $X/clip.tsv)
chk "x11 acquired-time logic (ts=$TS now=$NOW est=$EST)" "{ [ \"$TS\" -le \"$NOW\" ] && echo \"$EST\" | grep -q '^20'; } || { [ \"$TS\" -gt \"$NOW\" ] && [ \"$EST\" = - ]; }"
head -c 3000000 /dev/urandom | base64 > $X/big.txt; xclip -selection clipboard < $X/big.txt; sleep 1
$E $B/c0f-x11 -d :99 -a $X/auth clipboard $X/clip2 > $X/clip2.tsv 2>&1
F=$(awk -F'\t' '$1=="CLIPBOARD" && $7=="UTF8_STRING"{print $12}' $X/clip2.tsv)
chk "x11 large clipboard via INCR (4 MB) identical" "grep -q OK_INCR $X/clip2.tsv && cmp -s $X/big.txt $X/clip2/$F"
$E $B/c0f-x11 -d :99 -a $X/auth screenshot $X/shot.png 2>$X/shot.err
xwd -root -silent > $X/shot.xwd
python3 - $X/shot.png $X/shot.xwd > $X/png.chk 2>&1 <<'PY'
import sys,zlib,struct
d=open(sys.argv[1],'rb').read(); assert d[:8]==b'\x89PNG\r\n\x1a\n'; p=8; idat=b''; ok=True
while p<len(d):
    n,=struct.unpack('>I',d[p:p+4]); t=d[p+4:p+8]; body=d[p+8:p+8+n]; crc,=struct.unpack('>I',d[p+8+n:p+12+n])
    ok &= (zlib.crc32(t+body)&0xffffffff)==crc
    if t==b'IHDR': w,h=struct.unpack('>II',body[:8])
    if t==b'IDAT': idat+=body
    p+=12+n
raw=zlib.decompress(idat)
x=open(sys.argv[2],'rb').read(); hs,=struct.unpack('>I',x[:4]); f=struct.unpack('>25I',x[:100]); bo=f[7]; bpl=f[12]; ncol=f[19]
pix=x[hs+ncol*12:]; diff=0
for yy in range(h):
    row=raw[yy*(1+3*w)+1:(yy+1)*(1+3*w)]
    for xx in range(0,w,7):
        v=pix[yy*bpl+4*xx:yy*bpl+4*xx+4]; v=struct.unpack('<I' if bo==0 else '>I',v)[0]
        if (row[3*xx],row[3*xx+1],row[3*xx+2])!=((v>>16)&255,(v>>8)&255,v&255): diff+=1
print('crc_ok',ok,'size',w,h,'pixel_diffs',diff)
PY
chk "x11 screenshot PNG valid + equals xwd pixels" "grep -q 'crc_ok True size 800 600 pixel_diffs 0' $X/png.chk"
printf 'wrongwrongwrongw' > $X/bad; xauth -f $X/badauth add :99 MIT-MAGIC-COOKIE-1 00112233445566778899aabbccddeeff 2>/dev/null
$E $B/c0f-x11 -d :99 -a $X/badauth info > /dev/null 2>$X/bad.err; R=$?
chk "x11 wrong cookie -> exit 3 + reason" "[ $R = 3 ] && grep -qi 'refused' $X/bad.err"
cat $X/png.chk; kill $TP $XP 2>/dev/null; pkill -f '[x]clip -selection' 2>/dev/null; sleep 1
echo "RESULT pass=$pass fail=$fail"
