'use strict';
/**
 * VinGuard — standalone HTTP server.
 *
 *   GET  /        demo page (open in a browser, try the samples)
 *   GET  /health  { ok: true }
 *   POST /agent   platform endpoint. HMAC-verified (x-agent-games-signature
 *                 over the raw body). Accepts:
 *                   { type: "agent-games.preflight.v1", ... }
 *                     -> { ok: true, protocolVersion: "v1" }, signed
 *                   { type: "vinguard.screen.v1", task_id, input: { chainId,
 *                     from, to, data, value } }
 *                     -> signed screening verdict (APPROVE / REVIEW / REJECT)
 *   POST /demo    public demo of the same screening logic, no HMAC.
 *                 Body: { from, to, data, value } or { sample: "<name>" }.
 *                 Rate-limited, unsigned, clearly labelled demo:true.
 *
 * Secrets come from the environment only (AGENT_GAMES_HMAC_SECRET).
 * The server never signs anything, holds no keys, moves no funds.
 */
const http = require('http');
const { signHex, verifyHex } = require('./src/hmac');
const { screen } = require('./src/screen');
const { SAMPLES } = require('./src/samples');

const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const SCREEN_TIMEOUT_MS = 50000;

// In-memory demo rate limit: 20 requests / minute / IP.
const demoHits = new Map();
function demoAllowed(ip) {
  const now = Date.now();
  const arr = (demoHits.get(ip) || []).filter((t) => now - t < 60000);
  if (arr.length >= 20) return false;
  arr.push(now);
  demoHits.set(ip, arr);
  return true;
}

function sendJson(res, status, obj, secret) {
  const raw = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (secret) headers['x-agent-games-signature'] = signHex(secret, raw);
  res.writeHead(status, headers);
  res.end(raw);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function withTimeout(promise, ms, onTimeout) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(onTimeout()), ms)),
  ]);
}

async function handleAgent(req, res) {
  const raw = await readBody(req);
  if (!SECRET) {
    return sendJson(res, 500, { error: 'agent secret not configured' });
  }
  if (!verifyHex(SECRET, raw, req.headers['x-agent-games-signature'])) {
    return sendJson(res, 401, { error: 'bad signature' });
  }
  let body;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch (_) {
    return sendJson(res, 400, { error: 'invalid JSON' }, SECRET);
  }

  if (body.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, SECRET);
  }

  if (body.type === 'vinguard.screen.v1') {
    const input = body.input || {};
    const verdict = await withTimeout(
      screen(input),
      SCREEN_TIMEOUT_MS,
      () => ({
        decision: 'REJECT',
        reason_code: 'TIMEOUT',
        summary: 'screening timed out — fail closed',
        decoded: { function: null, selector: null, args: {} },
        checks: [{ name: 'timeout', pass: false, detail: 'screening exceeded 50s' }],
        risks: ['TIMEOUT'],
        evidence: { blockNumber: null, simOk: false, returnData: null, gasEstimate: null, feeBnb: null, ms: SCREEN_TIMEOUT_MS },
        agentTimestamp: new Date().toISOString(),
      })
    );
    verdict.task_id = body.task_id || null;
    verdict.idempotencyKey = body.task_id || null;
    return sendJson(res, 200, verdict, SECRET);
  }

  return sendJson(res, 400, { error: 'unknown task type', supported: ['agent-games.preflight.v1', 'vinguard.screen.v1'] }, SECRET);
}

async function handleDemo(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!demoAllowed(ip)) {
    res.writeHead(429, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ error: 'demo rate limit: 20 requests/minute' }));
  }
  const raw = await readBody(req);
  let body = {};
  try { body = JSON.parse(raw.toString('utf8') || '{}'); } catch (_) { /* fall through */ }
  let input = body.input || body;
  if (body.sample && SAMPLES[body.sample]) input = SAMPLES[body.sample].input;
  const verdict = await withTimeout(screen(input), SCREEN_TIMEOUT_MS, () => ({
    decision: 'REJECT', reason_code: 'TIMEOUT', summary: 'screening timed out — fail closed',
    decoded: { function: null, selector: null, args: {} },
    checks: [{ name: 'timeout', pass: false, detail: 'screening exceeded 50s' }],
    risks: ['TIMEOUT'],
    evidence: { blockNumber: null, simOk: false, returnData: null, gasEstimate: null, feeBnb: null, ms: SCREEN_TIMEOUT_MS },
    agentTimestamp: new Date().toISOString(),
  }));
  verdict.demo = true;
  sendJson(res, 200, verdict);
}

const DEMO_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>VinGuard — BSC Transaction Guard Agent</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}pre{background:#111;color:#0f0;padding:12px;overflow:auto;border-radius:8px}button{margin:4px 8px 4px 0;padding:8px 12px;cursor:pointer}</style></head>
<body>
<h1>VinGuard</h1>
<p>A BSC transaction guard agent for the zkVerify Agent Games (Wildcard track).
Paste any BSC transaction below — the agent simulates it with <code>eth_call</code>, decodes it,
checks the contract, and returns <b>APPROVE / REVIEW / REJECT</b> with a one-line summary.
Read-only: it never signs, holds no keys, moves no funds.</p>
<h2>Try a sample</h2>
<div id="samples"></div>
<h2>Or screen your own</h2>
<p><label>from <input id="from" size="44" value="0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09"></label></p>
<p><label>to <input id="to" size="44" value="0x55d398326f99059fF775485246999027B3197955"></label></p>
<p><label>data <input id="data" size="70" value="0x095ea7b3"></label></p>
<p><label>value (wei) <input id="value" size="24" value="0"></label></p>
<button onclick="run()">Screen it</button>
<pre id="out">Result appears here.</pre>
<script>
const samples = ${JSON.stringify(Object.fromEntries(Object.entries(SAMPLES).map(([k, v]) => [k, v.label])))};
const box = document.getElementById('samples');
for (const [k, label] of Object.entries(samples)) {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = () => post({ sample: k });
  box.appendChild(b);
}
async function post(body) {
  document.getElementById('out').textContent = 'Screening…';
  const r = await fetch('/demo', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}
function run() {
  post({ from: document.getElementById('from').value, to: document.getElementById('to').value, data: document.getElementById('data').value, value: document.getElementById('value').value });
}
</script>
<p><small>Platform endpoint: <code>POST /agent</code> (HMAC-signed, preflight + <code>vinguard.screen.v1</code>). Public demo: <code>POST /demo</code>. Source &amp; docs in the repo README.</small></p>
</body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(DEMO_PAGE);
    }
    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, { ok: true, service: 'vinguard', version: '1.0.0' });
    }
    if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/api/agent')) return handleAgent(req, res);
    if (req.method === 'POST' && (url.pathname === '/demo' || url.pathname === '/api/demo')) return handleDemo(req, res);
    return sendJson(res, 404, { error: 'not found', endpoints: ['GET /', 'GET /health', 'POST /agent', 'POST /demo'] });
  } catch (e) {
    return sendJson(res, 500, { error: e.message || 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`VinGuard listening on :${PORT} (secret ${SECRET ? 'configured' : 'NOT SET — /agent will 500'})`);
  });
}

// Vercel treats a root server.js as the deployment entrypoint and requires
// the default export to be a function or a server — so the server itself is
// the default export, with SAMPLES / DEMO_PAGE attached for api/index.js.
module.exports = server;
module.exports.SAMPLES = SAMPLES;
module.exports.DEMO_PAGE = DEMO_PAGE;
