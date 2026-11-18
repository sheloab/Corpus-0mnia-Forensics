#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
"""Turn a `script --log-out/--log-timing` recording into a looping animated terminal SVG and a plain transcript.
usage: mksvg.py LOG TIMING OUT.svg OUT.txt"""
import html, re, sys

LOG, TIM, SVG, TXT = sys.argv[1:5]
raw = open(LOG, 'rb').read()
tim = [(float(d), int(b)) for d, b in (l.split() for l in open(TIM))]
start = raw.find(b'\n') + 1                      # skip the "Script started" header
stream, t, pos = [], 0.0, start
for d, b in tim:
    t += min(d, 0.9)                             # long waits are shortened in the animation
    stream.append((t, raw[pos:pos + b])); pos += b

ansi = re.compile(rb'\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]')
lines, cur, cur_t = [], b'', None
for t, chunk in stream:
    parts = ansi.sub(b'', chunk).split(b'\n')
    for i, p in enumerate(parts):
        if cur_t is None and p.strip(b'\r'):
            cur_t = t
        cur += p
        if i < len(parts) - 1:
            txt = cur.split(b'\r')
            txt = [x for x in txt if x] or [b'']
            lines.append((cur_t if cur_t is not None else t, txt[-1].decode('utf-8', 'replace').rstrip()))
            cur, cur_t = b'', None
if cur.strip():
    lines.append((cur_t or t, cur.decode('utf-8', 'replace').rstrip()))
lines = [(t, l) for t, l in lines if not l.startswith('Script done')]
while lines and not lines[-1][1].strip():
    lines.pop()

open(TXT, 'w').write('\n'.join(l for _, l in lines) + '\n')
wrapped = []                                     # the recording terminal was 110 columns wide
for t, l in lines:
    while len(l) > 110:
        wrapped.append((t, l[:110])); l = l[110:]
    wrapped.append((t, l))
lines = wrapped

ROWS, CW, LH, PAD, TOP = 34, 7.22, 17, 14, 34
cols = max(len(l) for _, l in lines)
W = int(PAD * 2 + cols * CW) + 4
H = TOP + ROWS * LH + PAD
END = lines[-1][0] + 6.0                         # hold the final screen 6 s, then loop
color = lambda l: ('#7ee787' if re.search(r'VERIFIED|status: COMPLETE|official C0F release key|signature +: OK', l) else
                   '#f2cc60' if re.search(r'WARNING|WARN|Type YES|^ !', l) else
                   '#79c0ff' if l.startswith('[C0F]') else
                   '#d2a8ff' if re.match(r'^(Save output|Case /|Examiner|Current time)', l) else
                   '#ff7b72' if 'CORPU5' in l else '#c9d1d9')
kt = lambda x: f'{min(max(x / END, 0), 1):.5f}'
o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
     f'font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="12">',
     '<title>C0F demo run</title>',
     f'<rect width="{W}" height="{H}" rx="8" fill="#0d1117"/>',
     '<circle cx="18" cy="16" r="5" fill="#ff5f56"/><circle cx="34" cy="16" r="5" fill="#ffbd2e"/>'
     '<circle cx="50" cy="16" r="5" fill="#27c93f"/>',
     f'<text x="{W / 2:.0f}" y="20" fill="#8b949e" text-anchor="middle">root@demo-server: /kit/c0f --out /evidence --no-ram --pcap-seconds 5</text>',
     f'<clipPath id="c"><rect x="0" y="{TOP - 4}" width="{W}" height="{ROWS * LH + 6}"/></clipPath>',
     '<g clip-path="url(#c)"><g>']
# scrolling: when line i appears and i >= ROWS, the block moves up so line i is the last visible row
vals, keys = ['0 0'], ['0']
for i, (t, _) in enumerate(lines):
    if i >= ROWS:
        vals.append(f'0 {-(i - ROWS + 1) * LH}'); keys.append(kt(t))
keys.append('1'); vals.append(vals[-1])
dedup_k, dedup_v = [], []
for k, v in zip(keys, vals):
    if dedup_k and k == dedup_k[-1]:
        dedup_v[-1] = v
    else:
        dedup_k.append(k); dedup_v.append(v)
o.append(f'<animateTransform attributeName="transform" type="translate" calcMode="discrete" dur="{END:.2f}s" '
         f'repeatCount="indefinite" values="{";".join(dedup_v)}" keyTimes="{";".join(dedup_k)}"/>')
for i, (t, l) in enumerate(lines):
    y = TOP + (i + 1) * LH - 4
    k = kt(t)
    anim = (f'<animate attributeName="opacity" calcMode="discrete" dur="{END:.2f}s" repeatCount="indefinite" '
            f'values="0;1" keyTimes="0;{k}"/>') if float(k) > 0 else ''
    o.append(f'<text x="{PAD}" y="{y}" fill="{color(l)}" opacity="{0 if anim else 1}" xml:space="preserve">'
             f'{html.escape(l)}{anim}</text>')
o.append('</g></g></svg>')
open(SVG, 'w').write('\n'.join(o) + '\n')
print(f'{len(lines)} lines, loop {END:.1f}s, {W}x{H}')
