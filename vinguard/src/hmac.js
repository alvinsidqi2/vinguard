'use strict';
/**
 * HMAC helpers for the Agent Games platform protocol.
 * The platform signs every inbound request with x-agent-games-signature:
 * HMAC-SHA256 (hex) over the RAW request body, keyed by the 32-byte secret
 * issued on the dashboard (Rotate Secret, shown once).
 * Every response we send is signed the same way, over the raw response body.
 */
const crypto = require('crypto');

function signHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

/** Accept a bare hex signature, or a `sha256=<hex>` prefixed one. */
function normalizeSig(header) {
  if (!header) return null;
  const h = String(header).trim().toLowerCase();
  return h.startsWith('sha256=') ? h.slice(7) : h;
}

/** Timing-safe comparison. Returns false on missing/malformed input. */
function verifyHex(secret, rawBody, header) {
  try {
    const given = normalizeSig(header);
    if (!given || !/^[0-9a-f]{64}$/.test(given)) return false;
    const expected = signHex(secret, rawBody);
    const a = Buffer.from(given, 'hex');
    const b = Buffer.from(expected, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

module.exports = { signHex, verifyHex, normalizeSig };
