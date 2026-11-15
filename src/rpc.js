'use strict';
/**
 * Minimal read-only BSC (chain 56) RPC client.
 * No keys, no signing, no funds — only eth_call / eth_getCode / eth_blockNumber
 * / eth_gasPrice / eth_estimateGas, plus a Sourcify verification lookup.
 * Dataseeds are rotated on failure; every call has a hard timeout so the
 * 60s platform deadline is never blown by a hung upstream.
 */
const RPCS = [
  'https://bsc-dataseed2.binance.org',
  'https://bsc-dataseed.binance.org',
  'https://bsc-dataseed1.bnbchain.org',
  'https://bsc-dataseed2.bnbchain.org',
];

const SOURCIFY = 'https://sourcify.dev/server/check-by-addresses';

async function postJson(url, body, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

async function getJson(url, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

/** Try each dataseed in order until one answers. Returns { result, rpc }. */
async function rpcCall(method, params, timeoutMs = 10000) {
  let lastErr = null;
  for (const rpc of RPCS) {
    try {
      const out = await postJson(
        rpc,
        { jsonrpc: '2.0', id: 1, method, params },
        timeoutMs
      );
      if (out.error) {
        // A JSON-RPC error is the chain answering, not a transport failure.
        // Execution errors (revert / insufficient funds / out of gas) mean
        // the transaction itself would fail — flag them so the screener can
        // report SIM_REVERT instead of a generic SIM_FAILED.
        const e = new Error(out.error.message || 'RPC error');
        e.isExecutionError = /insufficient funds|revert|execution|out of gas|intrinsic gas/i.test(e.message);
        e.rpcCode = out.error.code;
        throw e;
      }
      return { result: out.result, rpc };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('all BSC RPCs failed');
}

async function getBlockNumber() {
  const { result } = await rpcCall('eth_blockNumber', []);
  return parseInt(result, 16);
}

async function getCode(address) {
  const { result } = await rpcCall('eth_getCode', [address, 'latest']);
  return result;
}

async function getGasPrice() {
  const { result } = await rpcCall('eth_gasPrice', []);
  return BigInt(result);
}

/** Simulate a call exactly as the wallet would send it. */
async function simulateCall({ from, to, data, valueHex }) {
  const { result, rpc } = await rpcCall('eth_call', [
    { from, to, data, value: valueHex || '0x0' },
    'latest',
  ]);
  return { returnData: result, rpc };
}

async function estimateGas({ from, to, data, valueHex }) {
  const { result } = await rpcCall('eth_estimateGas', [
    { from, to, data, value: valueHex || '0x0' },
  ]);
  return BigInt(result);
}

/** Sourcify verification status: 'perfect' | 'partial' | false | 'unknown'. */
async function sourcifyStatus(address) {
  try {
    const url = `${SOURCIFY}?addresses=${address}&chainIds=56`;
    const out = await getJson(url, 8000);
    if (Array.isArray(out) && out.length > 0) {
      const s = out[0].status;
      return s === 'perfect' || s === 'partial' ? s : false;
    }
    return 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

module.exports = {
  getBlockNumber,
  getCode,
  getGasPrice,
  simulateCall,
  estimateGas,
  sourcifyStatus,
};
