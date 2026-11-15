'use strict';
/**
 * VinGuard screening logic — deterministic, read-only, fail-closed.
 *
 * Given one BSC transaction (from / to / data / value) it:
 *   1. simulates it with eth_call exactly as the wallet would send it,
 *   2. decodes the function selector and arguments,
 *   3. checks whether the target contract is verified (Sourcify),
 *   4. estimates the gas fee,
 *   5. returns one verdict: APPROVE / REVIEW / REJECT, with reason codes,
 *      a one-line human summary, and the evidence (block number, sim result).
 *
 * Policy (deliberate, documented in README):
 *   APPROVE only for: plain BNB transfer to an EOA, read-only calls, and
 *   free claims on contracts the owner has personally verified on-chain.
 *   REVIEW for: any finite token approval, any token movement, any unknown
 *   function, any unverified contract — the human decides, with the full
 *   decode in front of them.
 *   REJECT for: simulation revert, unlimited approval (2^256-1),
 *   setApprovalForAll(true), value sent with an unknown function, and
 *   value sent to an unverified contract. Never approve by default.
 */
const rpc = require('./rpc');

const MAX_UINT256 = (2n ** 256n) - 1n;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

// Function selectors we decode (first 4 bytes of calldata).
const FUNCTIONS = {
  '095ea7b3': { name: 'approve', args: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  a9059cbb: { name: 'transfer', args: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  '23b872dd': { name: 'transferFrom', args: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  a22cb465: { name: 'setApprovalForAll', args: [{ name: 'operator', type: 'address' }, { name: 'approved', type: 'bool' }] },
  '94bf804d': { name: 'mint', args: [{ name: 'shares', type: 'uint256' }, { name: 'to', type: 'address' }] },
  c114c615: { name: 'claimFreeSlot', args: [] },
  f366afc9: { name: 'claimFree', args: [] },
  '70a08231': { name: 'balanceOf', args: [{ name: 'account', type: 'address' }], view: true },
  dd62ed3e: { name: 'allowance', args: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], view: true },
  '18160ddd': { name: 'totalSupply', args: [], view: true },
  '6352211e': { name: 'ownerOf', args: [{ name: 'tokenId', type: 'uint256' }], view: true },
  '06fdde03': { name: 'name', args: [], view: true },
  '95d89b41': { name: 'symbol', args: [], view: true },
  '313ce567': { name: 'decimals', args: [], view: true },
};

// Free claims the owner has personally verified on-chain (value 0, sim must pass).
// Never add an entry here without a verified on-chain execution behind it.
const VERIFIED_FREE_CLAIMS = [
  { contract: '0x7d8e34cBbf5d171391f43154cc5B5334f40667c1', selector: 'c114c615', label: 'AGENT404 free slot (claimFreeSlot)' },
  { contract: '0xC3f847430D660e5AAbE8D4b2B5792d6Fcbb171F9', selector: 'f366afc9', label: 'Digital Bomb free claim (claimFree)' },
  { contract: '0xf08ac9c91dcfc5b74eae6c87e744cfefe0d32a68', selector: '94bf804d', label: 'NEBULA free share (mint 1)' },
];

// Human labels for addresses the owner actually uses (context only —
// a label never turns a REVIEW into an APPROVE).
const KNOWN_LABELS = {
  '0x1eea3629c7505dcf8c8d247558f6e244d19c60de': 'AgentsEstates market',
  '0x0233900626a04a79f1e3f1a58b989dca67c1c392': 'Nib market',
  '0x55d398326f99059ff775485246999027b3197955': 'USDT (BSC)',
  '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': 'WBNB',
};

function shortAddr(a) {
  if (!a) return '?';
  return a.slice(0, 6) + '…' + a.slice(-4);
}

function labelOf(a) {
  if (!a) return null;
  return KNOWN_LABELS[a.toLowerCase()] || null;
}

function formatBnb(wei) {
  const w = BigInt(wei);
  const whole = w / 10n ** 18n;
  const frac = (w % 10n ** 18n).toString().padStart(18, '0').slice(0, 6).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

function normalizeValue(value) {
  if (value === undefined || value === null || value === '') return 0n;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^\d+$/.test(s)) return BigInt(s);
  throw new Error('value must be a wei amount (hex or decimal string)');
}

function decodeCalldata(data) {
  const hex = (data || '0x').toLowerCase();
  if (hex === '0x' || hex.length < 10) return { selector: null, fn: null, args: {} };
  const selector = hex.slice(2, 10);
  const fn = FUNCTIONS[selector] || null;
  const args = {};
  if (fn) {
    const words = [];
    for (let i = 10; i + 64 <= hex.length; i += 64) words.push(hex.slice(i, i + 64));
    fn.args.forEach((spec, i) => {
      const w = words[i];
      if (w === undefined) return;
      if (spec.type === 'address') args[spec.name] = '0x' + w.slice(24);
      else if (spec.type === 'uint256') args[spec.name] = BigInt('0x' + w);
      else if (spec.type === 'bool') args[spec.name] = w.slice(-1) === '1';
      else args[spec.name] = '0x' + w;
    });
  }
  return { selector, fn, args };
}

/** Decode a revert reason from eth_call return data (Error(string)). */
function decodeRevert(returnData) {
  try {
    if (!returnData || !returnData.startsWith('0x08c379a0')) return null;
    const body = returnData.slice(10);
    const len = parseInt(body.slice(64, 128), 16);
    const strHex = body.slice(128, 128 + len * 2);
    return Buffer.from(strHex, 'hex').toString('utf8');
  } catch (_) {
    return null;
  }
}

/** A node error message may embed the raw Error(string) hex — extract the text. */
function extractRevertReason(msg) {
  const m = String(msg || '').match(/0x08c379a0[0-9a-fA-F]*/);
  return m ? decodeRevert(m[0]) : null;
}

function truncate(s, n) {
  const t = String(s || '');
  return t.length > n ? t.slice(0, n - 3) + '...' : t;
}

function isAddress(a) {
  return typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a);
}

/**
 * Screen one transaction. Input: { chainId, from, to, data, value }.
 * value may be a hex string, decimal string, or number (wei). Default 0.
 * Returns the verdict object (never throws on screening failure — a failure
 * to check is itself a REVIEW/REJECT, never an APPROVE).
 */
async function screen(input) {
  const checks = [];
  const risks = [];
  const started = Date.now();

  const chainId = Number(input.chainId || 56);
  const from = isAddress(input.from) ? input.from : ZERO_ADDRESS;
  const to = input.to;
  let valueWei;
  try {
    valueWei = normalizeValue(input.value);
  } catch (e) {
    return failClosed('INVALID_VALUE', e.message, checks, risks, started);
  }
  if (chainId !== 56) {
    return failClosed('UNSUPPORTED_CHAIN', `only BSC chain 56 is supported, got ${chainId}`, checks, risks, started);
  }
  if (!isAddress(to)) {
    return failClosed('INVALID_TARGET', 'to must be a 0x address', checks, risks, started);
  }
  const data = typeof input.data === 'string' && input.data.startsWith('0x') ? input.data : '0x';
  const valueHex = '0x' + valueWei.toString(16);

  const { selector, fn, args } = decodeCalldata(data);
  const fnName = fn ? fn.name : selector ? `unknown(0x${selector})` : '(plain transfer)';
  const toLabel = labelOf(to);
  const hasCodeP = rpc.getCode(to);
  const blockP = rpc.getBlockNumber();
  const gasPriceP = rpc.getGasPrice().catch(() => null);
  const simP = rpc.simulateCall({ from, to, data, valueHex });
  const verifyP = rpc.sourcifyStatus(to);
  const estimateP = rpc.estimateGas({ from, to, data, valueHex }).catch(() => null);

  const [codeRes, blockRes, simRes, verifyRes] = await Promise.allSettled([
    hasCodeP, blockP, simP, verifyP,
  ]);
  const code = codeRes.status === 'fulfilled' ? codeRes.value : null;
  const blockNumber = blockRes.status === 'fulfilled' ? blockRes.value : null;
  const verified = verifyRes.status === 'fulfilled' ? verifyRes.value : 'unknown';
  const hasCode = code !== null && code !== '0x' && code !== '0x0';

  checks.push({ name: 'target_has_code', pass: hasCode, detail: hasCode ? 'contract' : 'EOA (no code)' });
  checks.push({ name: 'contract_verified', pass: verified === 'perfect' || verified === 'partial', detail: verified === false ? 'not verified on Sourcify' : verified === 'unknown' ? 'verification lookup failed' : `Sourcify ${verified}` });
  if (verified === false) risks.push('UNVERIFIED_CONTRACT');
  if (verified === 'unknown') risks.push('VERIFICATION_UNKNOWN');

  // 1. Simulation must pass — a revert means the transaction cannot execute.
  // Distinguish a chain execution error (the tx would fail on-chain) from a
  // transport failure (we could not reach the chain at all).
  if (simRes.status !== 'fulfilled') {
    const execErr = simRes.reason && simRes.reason.isExecutionError;
    const msg = simRes.reason && simRes.reason.message ? simRes.reason.message : 'RPC error';
    const humanReason = extractRevertReason(msg);
    const shown = humanReason || truncate(msg, 160);
    checks.push({ name: 'simulation', pass: false, detail: execErr ? `chain refuses the call: ${shown}` : `eth_call failed: ${shown}` });
    return buildVerdict({
      decision: 'REJECT', reason: execErr ? 'SIM_REVERT' : 'SIM_FAILED',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} · value ${formatBnb(valueWei)} BNB · ${execErr ? `would fail on-chain: ${shown}` : 'simulation could not run — fail closed'}`,
      decoded: { function: fnName, selector, args: stringifyArgs(args) },
      checks, risks, blockNumber, simOk: false, returnData: null, gasEstimate: null, feeBnb: null, started,
    });
  }
  const simReturn = simRes.value.returnData;
  checks.push({ name: 'simulation', pass: true, detail: 'eth_call succeeded' });

  // The sim result itself can carry a revert: eth_call returns an error for
  // reverts on most nodes, but a returned Error(string) payload is also a revert.
  const revertReason = decodeRevert(simReturn);
  if (revertReason) {
    checks.push({ name: 'revert_reason', pass: false, detail: revertReason });
    return buildVerdict({
      decision: 'REJECT', reason: 'SIM_REVERT',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} · value ${formatBnb(valueWei)} BNB · reverts on-chain: "${revertReason}"`,
      decoded: { function: fnName, selector, args: stringifyArgs(args) },
      checks, risks, blockNumber, simOk: false, returnData: simReturn, gasEstimate: null, feeBnb: null, started,
    });
  }

  // Fee estimate (best effort — a missing estimate never blocks a verdict).
  const gasPrice = await gasPriceP;
  const gasEstimate = await estimateP;
  const feeBnb = gasPrice !== null && gasEstimate !== null
    ? formatBnb(gasPrice * gasEstimate)
    : null;

  const decoded = { function: fnName, selector, args: stringifyArgs(args) };
  const base = { decoded, checks, risks, blockNumber, simOk: true, returnData: simReturn ? simReturn.slice(0, 66) : null, gasEstimate: gasEstimate ? gasEstimate.toString() : null, feeBnb, started };

  // 2. Unlimited approval — the single most dangerous common action.
  if (selector === '095ea7b3') {
    const spender = args.spender;
    const amount = args.amount;
    const spenderLabel = labelOf(spender);
    if (amount === MAX_UINT256) {
      risks.push('UNLIMITED_APPROVAL');
      return buildVerdict({
        decision: 'REJECT', reason: 'UNLIMITED_APPROVAL',
        summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · approve UNLIMITED to ${shortAddr(spender)}${spenderLabel ? ` (${spenderLabel})` : ''} · fee ~${feeBnb || '?'} BNB`,
        ...base,
      });
    }
    return buildVerdict({
      decision: 'REVIEW', reason: 'FINITE_APPROVAL',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · approve ${formatAmount(amount, to)} to ${shortAddr(spender)}${spenderLabel ? ` (${spenderLabel})` : ''} · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 3. Operator approval for a whole collection.
  if (selector === 'a22cb465') {
    const operator = args.operator;
    if (args.approved === true) {
      risks.push('OPERATOR_APPROVAL');
      return buildVerdict({
        decision: 'REJECT', reason: 'OPERATOR_APPROVAL',
        summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · setApprovalForAll(true) to operator ${shortAddr(operator)} — whole collection at risk · fee ~${feeBnb || '?'} BNB`,
        ...base,
      });
    }
    return buildVerdict({
      decision: 'APPROVE', reason: 'REVOKE_OPERATOR',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · setApprovalForAll(false) — revokes operator ${shortAddr(operator)} · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 4. Token movement to a third party — always a human decision.
  if (selector === 'a9059cbb' || selector === '23b872dd') {
    return buildVerdict({
      decision: 'REVIEW', reason: 'TOKEN_TRANSFER',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} ${formatAmount(args.amount, to)} → ${shortAddr(args.to || args.from)} · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 5. Plain BNB transfer to an EOA — the only value movement auto-approved.
  if (!hasCode) {
    if (data !== '0x') {
      return buildVerdict({
        decision: 'REVIEW', reason: 'DATA_TO_EOA',
        summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)} (EOA) · calldata sent to an address with no code — almost certainly a mistake · value ${formatBnb(valueWei)} BNB · fee ~${feeBnb || '?'} BNB`,
        ...base,
      });
    }
    return buildVerdict({
      decision: 'APPROVE', reason: 'PLAIN_TRANSFER',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)} (EOA) · plain transfer ${formatBnb(valueWei)} BNB · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 6. Value sent to a contract.
  if (valueWei > 0n) {
    if (!fn) {
      risks.push('UNKNOWN_CALL_WITH_VALUE');
      return buildVerdict({
        decision: 'REJECT', reason: 'UNKNOWN_CALL_WITH_VALUE',
        summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · unknown function 0x${selector} with ${formatBnb(valueWei)} BNB attached · fee ~${feeBnb || '?'} BNB`,
        ...base,
      });
    }
    if (verified === false) {
      risks.push('VALUE_TO_UNVERIFIED');
      return buildVerdict({
        decision: 'REJECT', reason: 'VALUE_TO_UNVERIFIED',
        summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)} (unverified) · ${fnName} with ${formatBnb(valueWei)} BNB attached · fee ~${feeBnb || '?'} BNB`,
        ...base,
      });
    }
    return buildVerdict({
      decision: 'REVIEW', reason: 'VALUE_CALL',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} with ${formatBnb(valueWei)} BNB attached · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 7. Verified free claims (value 0, simulation already passed).
  const freeClaim = VERIFIED_FREE_CLAIMS.find(
    (c) => c.contract.toLowerCase() === to.toLowerCase() && c.selector === selector
  );
  if (freeClaim) {
    return buildVerdict({
      decision: 'APPROVE', reason: 'VERIFIED_FREE_CLAIM',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)} · ${freeClaim.label} · value 0 · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }

  // 8. Read-only calls cannot move anything.
  if (fn && fn.view) {
    return buildVerdict({
      decision: 'APPROVE', reason: 'READ_ONLY',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} (read-only, no state change) · value 0`,
      ...base,
    });
  }

  // 9. Anything else, value 0: explain it, let the human decide.
  if (!fn) {
    return buildVerdict({
      decision: 'REVIEW', reason: 'UNKNOWN_FUNCTION',
      summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · unknown function 0x${selector} · value 0 · fee ~${feeBnb || '?'} BNB`,
      ...base,
    });
  }
  return buildVerdict({
    decision: 'REVIEW', reason: 'KNOWN_CALL',
    summary: `BSC 56 · from ${shortAddr(from)} · to ${shortAddr(to)}${toLabel ? ` (${toLabel})` : ''} · ${fnName} · value 0 · fee ~${feeBnb || '?'} BNB`,
    ...base,
  });
}

function formatAmount(amount, tokenContract) {
  if (amount === undefined) return '';
  // Amounts are raw token units; without decimals we show the raw value.
  // (The one-line summary keeps the raw units so nothing is ever mis-scaled.)
  return `${amount.toString()} units`;
}

function stringifyArgs(args) {
  const out = {};
  for (const [k, v] of Object.entries(args || {})) {
    out[k] = typeof v === 'bigint' ? v.toString() : v;
  }
  return out;
}

function buildVerdict({ decision, reason, summary, decoded, checks, risks, blockNumber, simOk, returnData, gasEstimate, feeBnb, started }) {
  return {
    decision,
    reason_code: reason,
    summary,
    decoded,
    checks,
    risks,
    evidence: {
      blockNumber,
      simOk,
      returnData,
      gasEstimate,
      feeBnb,
      ms: Date.now() - started,
    },
    agentTimestamp: new Date().toISOString(),
  };
}

function failClosed(reason, detail, checks, risks, started) {
  checks.push({ name: 'input', pass: false, detail });
  return buildVerdict({
    decision: 'REJECT', reason, summary: `screening refused: ${detail}`,
    decoded: { function: null, selector: null, args: {} },
    checks, risks, blockNumber: null, simOk: false, returnData: null,
    gasEstimate: null, feeBnb: null, started,
  });
}

module.exports = { screen, FUNCTIONS, VERIFIED_FREE_CLAIMS };
