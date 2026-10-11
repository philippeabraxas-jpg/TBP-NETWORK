#!/usr/bin/env node
// browser-dump.js — opens a page in a headless Chrome/Chromium, waits, and prints {title, html} of what the page
// actually became (its scripts have run). Used by test_site.sh to check that the live console shows what it must and
// never runs anything a request put in it. No dependency: Node's own WebSocket and the DevTools protocol.
//
//   node browser-dump.js <chrome binary> <url> [wait milliseconds]

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const [chrome, url, waitArg] = process.argv.slice(2);
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
setTimeout(() => finish(3), wait + 20000).unref();

let buf = '';
child.stderr.on('data', (d) => {
  buf += d.toString();
  const m = buf.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
  if (m) { buf = ''; setTimeout(() => inspect(parseInt(m[1], 10)), wait); }
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
    ws.onopen = async () => {
      const t = await send('Runtime.evaluate', { expression: 'document.title', returnByValue: true });
      const h = await send('Runtime.evaluate', { expression: 'document.documentElement.outerHTML', returnByValue: true });
      finish(0, { title: t.result.result.value, html: h.result.result.value });
    };
  } catch (e) { finish(6); }
}
