#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
"""Build docs/demo.html: a terminal simulator that replays REAL recorded C0F output.
usage: mkdemo.py RECDIR OUT.html
RECDIR: demo.raw + demo.tim (interactive run), int-abort.raw, int-ctrlc.raw, yes-run.raw, help.txt, err/*.txt"""
import json, os, re, sys

R, OUT = sys.argv[1], sys.argv[2]
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]')


def clean_lines(raw):
    out = []
    for l in ANSI.sub('', raw).split('\n'):
        parts = [p for p in l.split('\r') if p] or ['']
        out.append(parts[-1].rstrip())
    return out


def timed_lines(log, tim):
    raw = open(log, 'rb').read()
    start = raw.find(b'\n') + 1
    t, pos, lines, cur, cur_t = 0.0, start, [], b'', None
    for d, b in ((float(a), int(b)) for a, b in (l.split() for l in open(tim))):
        t += d
        chunk = re.sub(rb'\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]', b'', raw[pos:pos + b]); pos += b
        parts = chunk.split(b'\n')
        for i, p in enumerate(parts):
            if cur_t is None and p.strip(b'\r'):
                cur_t = t
            cur += p
            if i < len(parts) - 1:
                seg = [x for x in cur.split(b'\r') if x] or [b'']
                lines.append((cur_t if cur_t is not None else t, seg[-1].decode('utf-8', 'replace').rstrip()))
                cur, cur_t = b'', None
    return lines


def untimed(path):
    ls = clean_lines(open(path, encoding='utf-8', errors='replace').read())
    return [l for l in ls if not l.startswith('Script started') and not l.startswith('Script done')]


PROMPTS = ["Save output to [", "Case / ticket number: ", "Examiner name: ",
           "Current time from a TRUSTED clock (phone/GPS), UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip: ",
           "Examiner note (free text, Enter to skip): ", "Type YES to continue, anything else to abort: ",
           "Current time from a TRUSTED clock again (UTC 'YYYY-MM-DD HH:MM:SS', Enter to skip): ",
           "Examiner closing note (Enter to skip): "]
KEYS = ["out", "case", "examiner", "clock1", "note", "yes", "clock2", "note2"]


def steps(lines):
    """[(t, text)] -> [{o:text,d:delay}|{p:prompt,k:key,v:recorded answer,d:delay}]"""
    st, last = [], lines[0][0] if lines else 0
    for t, l in lines:
        d = round(min(max(t - last, 0), 1.2), 2); last = t
        for p, k in zip(PROMPTS, KEYS):
            if l.startswith(p.rstrip()):
                if k == "out":
                    i = l.index("]:") + 2
                    st.append({"p": l[:i] + " ", "k": k, "v": l[i:].strip(), "d": d})
                else:
                    st.append({"p": p, "k": k, "v": l[len(p):].strip(), "d": d})
                break
        else:
            st.append({"o": l, "d": d})
    return st


demo = timed_lines(os.path.join(R, 'demo.raw'), os.path.join(R, 'demo.tim'))
demo = [(t, l) for t, l in demo if not l.startswith('Script done') and not l.startswith('[exit code')]
while demo and not demo[-1][1].strip():
    demo.pop()
S = steps(demo)
# split: header (banner + verification, up to the Host line) | interactive part
hi = next(i for i, s in enumerate(S) if s.get("o", "").startswith("[C0F] Host "))
HEAD, INTER = S[:hi + 1], S[hi + 1:]


def after(lines, marker, inclusive=True):
    i = next(i for i, l in enumerate(lines) if marker in l)
    return lines[i if inclusive else i + 1:]


def plain_steps(lines, d=0.05):
    return steps([(i * d, l) for i, l in enumerate(lines)])


abort = after(untimed(os.path.join(R, 'int-abort.raw')), "Type YES to continue", inclusive=False)
abort = [l for l in abort if l.strip()]
ctrl = untimed(os.path.join(R, 'int-ctrlc.raw'))
ctrl_tail = after(ctrl, "WARN interrupted by operator")
ctrl_tail[0] = ctrl_tail[0].replace('^C', '')
ctrl_at = [l for l in ctrl if re.match(r'\[C0F\] \(\d+/227\)', l)][-1]
yes = untimed(os.path.join(R, 'yes-run.raw'))
yes = after(yes, "[C0F] Self-test of kit tools")
yes = [l for l in yes if not l.startswith('[exit code')]
helptxt = open(os.path.join(R, 'help.txt')).read().rstrip('\n').split('\n')

ERR = {}
for f in sorted(os.listdir(os.path.join(R, 'err'))):
    if f.endswith('.txt'):
        ls = untimed(os.path.join(R, 'err', f))
        ERR[f[:-4]] = [l for l in ls if l.strip() and not l.startswith('### ') and not l.startswith('$ ')]
err_line = lambda k, pat: next(l for l in ERR[k] if pat in l)

DATA = {
    "head": HEAD, "inter": INTER,
    "abort": [l for l in abort if not l.startswith('[exit code')],
    "ctrl": plain_steps([l for l in ctrl_tail if not l.startswith('[exit code')]),
    "ctrlAt": ctrl_at,
    "yes": plain_steps(yes, 0.12),
    "help": helptxt,
    "e_yes": err_line('05-yes-no-case', '--yes needs'),
    "e_root": err_line('06-not-root', 'must run as root'),
    "e_tmpfs": err_line('07-tmpfs-out', 'is in RAM'),
    "e_ro": err_line('08-readonly-out', 'cannot create output folder'),
    "e_unknown": err_line('01-unknown-option', 'unknown option'),
    "e_pcap": err_line('02-pcap-seconds', '--pcap-seconds'),
    "e_tf": err_line('03-timeout-factor', '--timeout-factor'),
    "e_since": err_line('04-since', '--since'),
}

HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>C0F terminal demo</title>
<style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;--blue:#79c0ff;--green:#7ee787;
--yellow:#f2cc60;--red:#ff7b72;--violet:#d2a8ff;--accent:#58a6ff}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px;max-width:1100px;margin:auto}
h1{font-size:20px;margin:4px 0 2px}p{margin:4px 0 10px;color:var(--dim)}
.bar{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
button{font:inherit;font-size:13px;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:6px;
padding:5px 10px;cursor:pointer}button:hover{border-color:var(--accent)}button.main{background:#1f6feb;border-color:#1f6feb;color:#fff}
.term{background:#010409;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.tb{display:flex;align-items:center;gap:6px;padding:8px 10px;background:var(--panel);border-bottom:1px solid var(--line);color:var(--dim);font-size:12px}
.tb i{width:11px;height:11px;border-radius:50%;display:inline-block}
#scr{height:min(62vh,560px);overflow:auto;padding:10px 12px;font:12.5px/1.42 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
white-space:pre-wrap;word-break:break-all;cursor:text}
#scr div{min-height:1.42em}.b{color:var(--blue)}.g{color:var(--green)}.y{color:var(--yellow)}.r{color:var(--red)}.v{color:var(--violet)}.d{color:var(--dim)}
.u{color:#fff}#in{background:transparent;border:0;outline:0;color:#fff;font:inherit;padding:0;width:60%;caret-color:var(--green)}
.hint{font-size:12px;color:var(--dim);margin-top:8px}code{background:var(--panel);padding:1px 4px;border-radius:4px}
</style></head><body>
<h1>Corpus-0mnia Forensics (C0F) - terminal demo</h1>
<p>Type a command, or click one below. Everything the "server" prints is the real output recorded from C0F 1.0.0
runs on a test server named <code>demo-server</code>; only the timing is shortened.</p>
<div class="bar" id="cmds"></div>
<div class="bar"><button class="main" id="auto">&#9654; Play full run (auto answers)</button>
<button id="speed">Speed: 1x</button><button id="ctrlc">Send Ctrl+C</button><button id="clear">Clear</button></div>
<div class="term"><div class="tb"><i style="background:#ff5f56"></i><i style="background:#ffbd2e"></i><i style="background:#27c93f"></i>
<span style="margin-left:8px">analyst@demo-server: /kit</span></div><div id="scr"></div></div>
<div class="hint">Shell commands: <code>help</code> <code>ls</code> <code>clear</code>. During a run: answer the prompts
(Enter accepts the value shown in the recording), press <code>Ctrl+C</code> to interrupt.</div>
<script>
const D = __DATA__;
const scr = document.getElementById('scr');
let speed = 1, busy = false, intr = false, autoMode = false, waitRes = null, shellPrompt = null;
const CMDS = ['sudo ./c0f', 'sudo ./c0f --yes --case IR-2026-0042 --examiner "J. Analyst" --out /evidence',
  './c0f --help', './c0f --fast', './c0f --pcap-seconds abc', './c0f --timeout-factor 0', 'sudo ./c0f --yes --out /evidence',
  'sudo ./c0f --out /dev/shm/evidence', 'ls'];
const cmdBar = document.getElementById('cmds');
CMDS.forEach(c => { const b = document.createElement('button'); b.textContent = c; b.onclick = () => runTyped(c); cmdBar.appendChild(b); });
function cls(t) {
  if (/VERIFIED|status: COMPLETE|official C0F release key|signature +: OK/.test(t)) return 'g';
  if (/ERROR|FAILED|Aborted|CORPU5|COMPROMISED|NOT CREATED/.test(t)) return 'r';
  if (/WARN|WARNING|INTERRUPTED|^ !/.test(t)) return 'y';
  if (/^\[C0F\]/.test(t)) return 'b';
  return '';
}
function line(t, c) { const d = document.createElement('div'); d.className = c === undefined ? cls(t) : c; d.textContent = t; scr.appendChild(d); scr.scrollTop = scr.scrollHeight; return d; }
const sleep = s => new Promise(r => setTimeout(r, s * 1000 / speed));
function ask(prompt, def, cls_) {
  return new Promise(res => {
    const d = line('', cls_ || 'v'); d.append(prompt);
    const inp = document.createElement('input'); inp.id = 'in'; inp.autocomplete = 'off'; inp.spellcheck = false;
    d.appendChild(inp); inp.focus();
    const done = v => { inp.remove(); const s = document.createElement('span'); s.className = 'u'; s.textContent = v; d.appendChild(s); waitRes = null; res(v); };
    waitRes = done;
    if (autoMode) { let i = 0; const typ = () => { if (waitRes !== done) return; if (i < def.length) { inp.value += def[i++]; setTimeout(typ, 35 / speed); } else setTimeout(() => waitRes === done && done(def), 300 / speed); }; setTimeout(typ, 400 / speed); }
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); done(inp.value === '' ? def : inp.value); }
      if (e.key === 'c' && e.ctrlKey) { e.preventDefault(); intr = true; done('^C'); }
    });
  });
}
function shell() {
  busy = false; autoMode = false;
  ask('analyst@demo-server:/kit$ ', '', 'g').then(c => { if (c && c !== '^C') runCmd(c); else shell(); });
}
function runTyped(c) {
  if (busy) return;
  if (waitRes) { const inp = document.getElementById('in'); if (inp) inp.value = c; waitRes(c); }
}
function tok(s) { const a = []; s.replace(/"([^"]*)"|'([^']*)'|(\S+)/g, (m, x, y, z) => a.push(x ?? y ?? z)); return a; }
async function out(lines, d) { for (const l of lines) { if (intr) return; line(l); await sleep(d ?? 0.02); } }
async function play(steps, ctx) {
  for (const s of steps) {
    if (intr) return 'int';
    await sleep(s.d);
    if (s.o !== undefined) { line(sub(s.o, ctx)); continue; }
    if ((s.k === 'case' && ctx.case) || (s.k === 'examiner' && ctx.examiner)) continue;
    const p = s.k === 'out' ? 'Save output to [' + ctx.out + ']: ' : s.p;
    let v = await ask(p, s.k === 'out' ? '' : s.v);
    if (intr) return 'int';
    if (s.k === 'out') { if (v) ctx.out = v; if (/^\/(dev\/shm|run)(\/|$)/.test(ctx.out)) { line('[C0F] Self-test of kit tools on this host ...'); line(D.e_tmpfs.replace('/ram/ev', ctx.out)); return 2; } }
    if (s.k === 'yes' && v !== 'YES') { await out(D.abort); return 2; }
  }
  return 0;
}
function sub(t, ctx) { return ctx.out === '/evidence' ? t : t.split('/evidence').join(ctx.out); }
async function runCmd(c) {
  busy = true; intr = false;
  const a = tok(c); let sudo = false;
  if (a[0] === 'sudo') { sudo = true; a.shift(); }
  const cmd = a.shift() || '';
  if (cmd === 'clear') { scr.innerHTML = ''; return shell(); }
  if (cmd === 'help') { await out(['Try: sudo ./c0f   |   sudo ./c0f --yes --case ID --examiner NAME --out /evidence   |   ./c0f --help', 'Wrong options are welcome: the demo shows the real error messages.'], 0); return shell(); }
  if (cmd === 'ls') { await out(['BUILDINFO.txt  LICENSES  README.txt  SHA256SUMS  SHA256SUMS.minisig  bin  c0f  c0f.sh  catalog.tsv  docs  lib  minisign.pub  os-profile.tsv  share'], 0); return shell(); }
  if (!/^(\.\/|\/kit\/)?c0f$/.test(cmd) || cmd === 'c0f') { line('sh: ' + (cmd === 'c0f' ? 'c0f: not found (use ./c0f)' : cmd + ': not found in this demo'), 'r'); return shell(); }
  const ctx = { out: '/kit/demo-server', case: '', examiner: '' }; let yes = false, rest = [];
  const ARG = ['--out', '--work', '--case', '--examiner', '--since', '--password', '--pcap-seconds', '--kubeconfig', '--timeout-factor', '--force-untrusted-kit'];
  const FLAG = ['--yes', '--no-ram', '--no-swap', '--no-pcap', '--no-timeline', '--no-e2image', '--no-container-export', '--no-db-binlogs', '--no-db-wal', '--no-db-data', '--no-process-dumps', '--no-screenshot', '--no-clipboard', '--password-prompt', '--dry-run', '--self-test', '--keep-work', '--no-timeout-prompt', '--no-banner', '--help', '-h', '--version'];
  const o = {};
  for (let i = 0; i < a.length; i++) {
    if (ARG.includes(a[i])) { o[a[i]] = a[++i] ?? ''; continue; }
    if (FLAG.includes(a[i])) { o[a[i]] = true; continue; }
    line(D.e_unknown.replace('--fast', a[i])); line('', ''); return shell();
  }
  if (o['--help'] || o['-h']) { await out(D.help, 0.01); return shell(); }
  if (o['--version']) { line('C0F 1.0.0', ''); return shell(); }
  const num = v => /^[0-9]+$/.test(v);
  if ('--since' in o && !num(o['--since'])) { line(D.e_since); return shell(); }
  if ('--pcap-seconds' in o && !num(o['--pcap-seconds'])) { line(D.e_pcap); return shell(); }
  if ('--timeout-factor' in o && !(num(o['--timeout-factor']) && +o['--timeout-factor'] >= 1 && +o['--timeout-factor'] <= 100)) { line(D.e_tf); return shell(); }
  if (o['--dry-run'] || o['--self-test']) { line('(demo) --dry-run and --self-test are not part of this recording: try them with a real kit.', 'd'); return shell(); }
  if (!sudo) { line('[C0F] Not running as root: re-starting with sudo (/usr/bin/sudo).'); await sleep(0.4); }
  if (o['--out']) ctx.out = o['--out']; ctx.case = o['--case'] || ''; ctx.examiner = o['--examiner'] || ''; yes = !!o['--yes'];
  let r = await play(D.head, ctx);
  if (r === 'int') return interrupted(false);
  if (/^\/(dev\/shm|run)(\/|$)/.test(ctx.out) && o['--out']) { line(D.e_tmpfs.replace('/ram/ev', ctx.out)); return shell(); }
  if (yes) {
    if (!ctx.case || !ctx.examiner) { line('[C0F] Self-test of kit tools on this host ...'); line(D.e_yes); return shell(); }
    line('(demo) unattended run: replaying a recorded --yes run', 'd');
    for (const s of D.yes) { if (intr) return interrupted(true); await sleep(s.d); line(sub(s.o ?? '', ctx)); }
    return shell();
  }
  r = await play(D.inter, ctx);
  if (r === 'int') return interrupted(true);
  shell();
}
async function interrupted(collecting) {
  intr = false;
  if (!collecting) { line('^C'); return shell(); }
  line('(demo) the lines below are the real output of a run interrupted after ' + D.ctrlAt.replace('[C0F] ', ''), 'd');
  await play(D.ctrl, { out: '/evidence' });
  shell();
}
document.getElementById('auto').onclick = () => { if (busy) return; autoMode = true; runTyped('sudo ./c0f'); setTimeout(() => autoMode = true, 50); };
document.getElementById('speed').onclick = e => { speed = speed === 1 ? 4 : speed === 4 ? 12 : 1; e.target.textContent = 'Speed: ' + speed + 'x'; };
document.getElementById('ctrlc').onclick = () => { if (busy) { intr = true; if (waitRes) waitRes('^C'); } };
document.getElementById('clear').onclick = () => { if (!busy) { scr.innerHTML = ''; if (waitRes) { waitRes(''); } } };
document.addEventListener('keydown', e => { if (e.key === 'c' && e.ctrlKey && busy && !waitRes) { intr = true; } });
scr.onclick = () => { const i = document.getElementById('in'); if (i) i.focus(); };
line('C0F terminal demo - type "help" or click a command above.', 'd');
shell();
if (location.hash === '#auto') { speed = 12; document.getElementById('auto').click(); }
</script></body></html>
'''
open(OUT, 'w').write(HTML.replace('__DATA__', json.dumps(DATA, ensure_ascii=False).replace('<', '\\u003c')))
print(f'{OUT}: head {len(HEAD)} steps, interactive {len(INTER)} steps, yes-run {len(DATA["yes"])} lines, {os.path.getsize(OUT)} bytes')
