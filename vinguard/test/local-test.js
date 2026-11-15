'use strict';
/**
 * Local test harness — replays the platform's preflight and sample screen
 * tasks against a live server, using real BSC RPC. No secrets, no funds.
 * Run:  node test/local-test.js
 * Exit 0 = all expectations met, 1 = something failed.
 */
const http = require('http');
const crypto = require('crypto');

const TEST_SECRET = 'test-secret-32-bytes-long-0123456789';
const PORT = 3456;

process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
process.env.PORT = String(PORT);
const { server } = require('../server');
const { signHex, verifyHex } = require('../src/hmac');

function post(path, bodyObj, sign) {
  const raw = JSON.stringify(bodyObj);
  return new Promise((resolve, reject) => {
    const headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) };
    if (sign) headers['x-agent-games-signature'] = signHex(TEST_SECRET, raw);
    const req = http.request({ host: '127.0.0.1', port: PORT, path, method: 'POST', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const rawRes = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(rawRes); } catch (_) { /* leave null */ }
        resolve({ status: res.statusCode, headers: res.headers, raw: rawRes, json });
      });
    });
    req.on('error', reject);
    req.write(raw);
    req.end();
  });
}

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

async function main() {
  await new Promise((resolve) => server.listen(PORT, resolve));
  console.log(`test server up on :${PORT}\n`);

  // 1. Preflight, correctly signed -> ok:true + valid response signature.
  const pre = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' }, true);
  check('preflight 200 + ok:true', pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === 'v1', `status=${pre.status}`);
  check('preflight response is HMAC-signed', verifyHex(TEST_SECRET, pre.raw, pre.headers['x-agent-games-signature']));

  // 2. Bad signature -> 401.
  const bad = await post('/agent', { type: 'agent-games.preflight.v1' }, false);
  check('unsigned request rejected 401', bad.status === 401, `status=${bad.status}`);

  // 3. Screen cases (live BSC RPC).
  const cases = [
    { name: 'plain transfer -> APPROVE', body: { type: 'vinguard.screen.v1', task_id: 't1', input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x067d4313a0b872f5f7279d3ce59d002c8f4694f3', data: '0x', value: '100000000000000' } }, want: 'APPROVE' },
    { name: 'unlimited approve -> REJECT', body: { type: 'vinguard.screen.v1', task_id: 't2', input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x55d398326f99059fF775485246999027B3197955', data: '0x095ea7b3' + '0000000000000000000000001eea3629c7505dcf8c8d247558f6e244d19c60de' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', value: '0' } }, want: 'REJECT' },
    { name: 'finite approve -> REVIEW', body: { type: 'vinguard.screen.v1', task_id: 't3', input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x55d398326f99059fF775485246999027B3197955', data: '0x095ea7b3' + '0000000000000000000000001eea3629c7505dcf8c8d247558f6e244d19c60de' + '0000000000000000000000000000000000000000000000056bc75e2d63100000', value: '0' } }, want: 'REVIEW' },
    // Today's A404 slot is already claimed (07:02 WIB), so the sim must revert.
    { name: 'a404 free slot (already claimed) -> REJECT/SIM_REVERT', body: { type: 'vinguard.screen.v1', task_id: 't4', input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x7d8e34cBbf5d171391f43154cc5B5334f40667c1', data: '0xc114c615', value: '0' } }, want: 'REJECT' },
    // 0.001 BNB exceeds the wallet's ~0.00036 BNB balance: the chain refuses it.
    { name: 'transfer above balance -> REJECT/SIM_REVERT', body: { type: 'vinguard.screen.v1', task_id: 't5', input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x067d4313a0b872f5f7279d3ce59d002c8f4694f3', data: '0x', value: '1000000000000000' } }, want: 'REJECT' },
  ];
  for (const c of cases) {
    const r = await post('/agent', c.body, true);
    const got = r.json && r.json.decision;
    check(c.name, r.status === 200 && got === c.want, `status=${r.status} decision=${got} reason=${r.json && r.json.reason_code} summary=${r.json && r.json.summary}`);
    if (r.json) {
      check(`  response signed (${c.name})`, verifyHex(TEST_SECRET, r.raw, r.headers['x-agent-games-signature']));
    }
  }

  // 4. Public demo, no HMAC.
  const demo = await post('/demo', { sample: 'unlimited-approve' }, false);
  check('demo unlimited-approve -> REJECT + demo:true', demo.status === 200 && demo.json && demo.json.decision === 'REJECT' && demo.json.demo === true, `status=${demo.status} decision=${demo.json && demo.json.decision}`);

  // 5. Unknown task type -> 400.
  const unk = await post('/agent', { type: 'agent-games.nope.v1' }, true);
  check('unknown task type -> 400', unk.status === 400, `status=${unk.status}`);

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  server.close();
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('TEST CRASH:', e);
  try { server.close(); } catch (_) { /* ignore */ }
  process.exit(1);
});
