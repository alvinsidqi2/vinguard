'use strict';
/**
 * Vercel serverless wrapper for POST /agent.
 * Reuses the same handler logic as server.js (HMAC verify, preflight,
 * vinguard.screen.v1). The HMAC secret comes from the
 * AGENT_GAMES_HMAC_SECRET environment variable set in the Vercel dashboard.
 *
 * The platform signs the RAW request body, so the body parser is disabled
 * and the raw stream is read directly — re-serializing parsed JSON would
 * change the bytes and break verification.
 */
const { signHex, verifyHex } = require('../src/hmac');
const { screen } = require('../src/screen');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const SCREEN_TIMEOUT_MS = 50000;

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function send(res, status, obj, sign) {
  const raw = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = signHex(SECRET, raw);
  res.status(status).setHeaders(headers).send(raw);
}

async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
  const raw = await readRaw(req);
  if (!SECRET) return send(res, 500, { error: 'agent secret not configured' });
  if (!verifyHex(SECRET, raw, req.headers['x-agent-games-signature'])) {
    return send(res, 401, { error: 'bad signature' });
  }
  let body;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch (_) {
    return send(res, 400, { error: 'invalid JSON' }, true);
  }
  if (body.type === 'agent-games.preflight.v1') {
    return send(res, 200, { ok: true, protocolVersion: 'v1' }, true);
  }
  if (body.type === 'vinguard.screen.v1') {
    const verdict = await Promise.race([
      screen(body.input || {}),
      new Promise((resolve) => setTimeout(() => resolve({
        decision: 'REJECT', reason_code: 'TIMEOUT', summary: 'screening timed out — fail closed',
        decoded: { function: null, selector: null, args: {} },
        checks: [{ name: 'timeout', pass: false, detail: 'screening exceeded 50s' }],
        risks: ['TIMEOUT'],
        evidence: { blockNumber: null, simOk: false, returnData: null, gasEstimate: null, feeBnb: null, ms: SCREEN_TIMEOUT_MS },
        agentTimestamp: new Date().toISOString(),
      }), SCREEN_TIMEOUT_MS)),
    ]);
    verdict.task_id = body.task_id || null;
    verdict.idempotencyKey = body.task_id || null;
    return send(res, 200, verdict, true);
  }
  return send(res, 400, { error: 'unknown task type', supported: ['agent-games.preflight.v1', 'vinguard.screen.v1'] }, true);
}

handler.config = { api: { bodyParser: false } };
module.exports = handler;
