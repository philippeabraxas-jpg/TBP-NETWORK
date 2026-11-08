#!/usr/bin/env node
// browser-dump.js — opens a page in a headless Chrome/Chromium, waits, and prints {title, html} of what the page
// actually became (its scripts have run). Used by test_site.sh to check that the live console shows what it must and
// never runs anything a request put in it. No dependency: Node's own WebSocket and the DevTools protocol.
//
//   node browser-dump.js <chrome binary> <url> [wait milliseconds [text the page must show]]
//
// With a text, the page is read as soon as it shows it (and a moment later, for what is drawn after it), or after the
// wait if it never does: a slow machine then costs time, not a false failure. Without one, it reads after the wait.

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const [chrome, url, waitArg, ready] = process.argv.slice(2);
const wait = parseInt(waitArg || '4000', 10);
if (!chrome || !url) { console.error('usage: browser-dump.js <chrome> <url> [ms]'); process.exit(2); }

if (typeof WebSocket === 'undefined') { console.error('browser-dump.js: this Node has no WebSocket (Node 22 or later)'); process.exit(7); }

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'browser-dump-'));
const env = Object.assign({}, process.env);
for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) delete env[k];
const child = spawn(chrome, ['--headless', '--no-sandbox', '--disable-gpu', '--no-proxy-server', '--disable-background-networking',
  '--disable-component-update', '--no-first-run', '--remote-debugging-port=0', '--user-data-dir=' + profile, url], { env, stdio: ['ignore', 'ignore', 'pipe'] });

let done = false;
function finish(code, out) {
  if (done) return;
  done = true;
  try { child.kill('SIGKILL'); } catch (e) { /* already gone */ }
  try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* best effort */ }
  if (out !== undefined) process.stdout.write(JSON.stringify(out));
  process.exit(code);
}
setTimeout(() => finish(3), wait + 30000).unref();

let buf = '';
child.stderr.on('data', (d) => {
  buf += d.toString();
  const m = buf.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
  if (m) { buf = ''; inspect(parseInt(m[1], 10)); }
});
child.on('exit', () => finish(3));

function getJSON(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p }, (res) => {
      let s = ''; res.on('data', (c) => (s += c)); res.on('end', () => { try { resolve(JSON.parse(s)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

async function inspect(port) {
  try {
    const pages = (await getJSON(port, '/json/list')).filter((t) => t.type === 'page');
    if (!pages.length) return finish(4);
    const ws = new WebSocket(pages[0].webSocketDebuggerUrl);
    let id = 0; const pending = new Map();
    const send = (method, params) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })); });
    ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
    ws.onerror = () => finish(5);
    // just after Chrome starts the page may not answer yet: an unanswered read is an empty page, read again
    const value = async (expression) => {
      const r = await send('Runtime.evaluate', { expression, returnByValue: true });
      const v = r && r.result && r.result.result && r.result.result.value;
      return typeof v === 'string' ? v : '';
    };
    const html = () => value('document.documentElement.outerHTML');
    ws.onopen = async () => {
      const started = Date.now();
      let h = await html();
      if (ready) {
        // poll until the page shows what it must, then let what is drawn after it settle
        while (!h.includes(ready) && Date.now() - started < wait) { await new Promise((r) => setTimeout(r, 200)); h = await html(); }
        if (h.includes(ready)) { await new Promise((r) => setTimeout(r, 500)); h = await html(); }
      } else {
        await new Promise((r) => setTimeout(r, wait)); h = await html();
      }
      finish(0, { title: await value('document.title'), html: h });
    };
  } catch (e) { finish(6); }
}
