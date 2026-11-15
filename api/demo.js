'use strict';
/**
 * Vercel serverless wrapper for POST /demo — public demo of the screening
 * logic, no HMAC. Same samples and policy as server.js.
 */
const { screen } = require('../src/screen');
const { SAMPLES } = require('../src/samples');

const SCREEN_TIMEOUT_MS = 50000;

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'POST only' });
    return;
  }
  const body = req.body || {};
  let input = body.input || body;
  if (body.sample && SAMPLES[body.sample]) input = SAMPLES[body.sample].input;
  const verdict = await Promise.race([
    screen(input),
    new Promise((resolve) => setTimeout(() => resolve({
      decision: 'REJECT', reason_code: 'TIMEOUT', summary: 'screening timed out — fail closed',
      decoded: { function: null, selector: null, args: {} },
      checks: [{ name: 'timeout', pass: false, detail: 'screening exceeded 50s' }],
      risks: ['TIMEOUT'],
      evidence: { blockNumber: null, simOk: false, returnData: null, gasEstimate: null, feeBnb: null, ms: SCREEN_TIMEOUT_MS },
      agentTimestamp: new Date().toISOString(),
    }), SCREEN_TIMEOUT_MS)),
  ]);
  verdict.demo = true;
  res.status(200).json(verdict);
};
