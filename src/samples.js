'use strict';
/**
 * Canned demo transactions for the public /demo endpoint and the demo page.
 * All from the owner's real on-chain history — no invented contracts.
 */
const SAMPLES = {
  'plain-transfer': {
    label: 'Plain BNB transfer (expect APPROVE)',
    input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x067d4313a0b872f5f7279d3ce59d002c8f4694f3', data: '0x', value: '100000000000000' },
  },
  'unlimited-approve': {
    label: 'Unlimited USDT approval (expect REJECT)',
    input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x55d398326f99059fF775485246999027B3197955', data: '0x095ea7b3' + '0000000000000000000000001eea3629c7505dcf8c8d247558f6e244d19c60de' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', value: '0' },
  },
  'finite-approve': {
    label: 'Finite USDT approval, 100 USDT (expect REVIEW)',
    input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x55d398326f99059fF775485246999027B3197955', data: '0x095ea7b3' + '0000000000000000000000001eea3629c7505dcf8c8d247558f6e244d19c60de' + '0000000000000000000000000000000000000000000000056bc75e2d63100000', value: '0' },
  },
  'a404-free-slot': {
    label: 'AGENT404 free slot claim (expect APPROVE if slot open, REJECT/SIM_REVERT if already claimed today)',
    input: { chainId: 56, from: '0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09', to: '0x7d8e34cBbf5d171391f43154cc5B5334f40667c1', data: '0xc114c615', value: '0' },
  },
};

module.exports = { SAMPLES };
