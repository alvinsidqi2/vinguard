# VinGuard — BSC Transaction Guard Agent

**Track:** zkVerify Agent Games 2026, Wildcard (Event 03)
**Owner:** Alvin — Binance Agentic Wallet `vinxs.ai` (`0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09`)

## The problem

AI agent wallets ask their owners to approve blockchain transactions the owner
cannot read. A raw transaction is a contract address plus opaque hex — the
owner taps "approve" in the app and hopes the agent (or the website that
generated the call) is honest. Unlimited token approvals, operator approvals
for whole NFT collections, and value sent to unverified contracts are all one
careless tap away. VinGuard exists so that tap is never blind.

## What it does

Given one BSC transaction (`from` / `to` / `data` / `value`), VinGuard:

1. **Simulates it** with `eth_call`, exactly as the wallet would send it.
   A revert means the transaction cannot execute — the agent says so, with the
   chain's own reason (e.g. `free taken`, `insufficient funds`).
2. **Decodes it** — function selector and arguments in plain language
   (`approve`, `transfer`, `setApprovalForAll`, `claimFreeSlot`, …).
3. **Checks the target** — code present? Verified on Sourcify? Known address?
4. **Estimates the fee** (gas × gas price, in BNB).
5. **Returns one verdict** — `APPROVE` / `REVIEW` / `REJECT` — with a reason
   code, a one-line human summary, and the evidence (block number, sim
   result, gas estimate). Every verdict cites the block it was computed at,
   so anyone can re-run the same `eth_call` and check it.

Read-only throughout. VinGuard never signs, holds no keys, moves no funds.

## Verdict policy (deterministic, fail-closed)

| Verdict | When |
|---|---|
| `APPROVE` | Plain BNB transfer to an EOA · read-only call · free claim on a contract the owner personally verified on-chain (AGENT404 mine, Digital Bomb, NEBULA) |
| `REVIEW` | Finite token approval · any token movement · unknown function · unverified contract — the human decides, with the full decode in front of them |
| `REJECT` | Simulation reverts · unlimited approval (`2^256-1`) · `setApprovalForAll(true)` · value sent with an unknown function · value sent to an unverified contract · any timeout or uncertainty |

The agent never approves by default. An approval to a *known* address is still
`REVIEW` unless it matches the narrow `APPROVE` list above — a label is
context, not trust.

Token amounts are reported in **raw units** in the decode, never silently
scaled by assumed decimals (a wrong decimal assumption is how listings get
mispriced by 10^18).

## Endpoints

| Route | What it is |
|---|---|
| `GET /` | Demo page — open in a browser, try the samples |
| `GET /health` | `{ ok: true }` |
| `POST /agent` | Platform endpoint. HMAC-verified (`x-agent-games-signature` over the raw body, HMAC-SHA256 hex, secret from the dashboard). Accepts the platform preflight (`agent-games.preflight.v1` → `{ ok: true, protocolVersion: "v1" }`, signed) and screen tasks (`vinguard.screen.v1`, see below). Every response is signed the same way. Unknown task types → 400, bad signature → 401. |
| `POST /demo` | Public demo of the same screening logic, no HMAC, rate-limited (20/min/IP), unsigned, labelled `demo: true`. Accepts `{ from, to, data, value }` or `{ sample: "<name>" }`. |

Screen task envelope:

```json
{
  "type": "vinguard.screen.v1",
  "task_id": "t-123",
  "input": {
    "chainId": 56,
    "from": "0x9AD98eE373e2fE53990032D709c6bB0eFCacCb09",
    "to": "0x55d398326f99059fF775485246999027B3197955",
    "data": "0x095ea7b3...",
    "value": "0"
  }
}
```

Response (signed):

```json
{
  "decision": "REJECT",
  "reason_code": "UNLIMITED_APPROVAL",
  "summary": "BSC 56 · from 0x9AD9…Cb09 · to 0x55d3…7955 (USDT (BSC)) · approve UNLIMITED to 0x1eea…60de (AgentsEstates market) · fee ~0.000002 BNB",
  "decoded": { "function": "approve", "selector": "095ea7b3", "args": { "spender": "0x…", "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" } },
  "checks": [ { "name": "simulation", "pass": true, "detail": "eth_call succeeded" } ],
  "risks": ["UNLIMITED_APPROVAL"],
  "evidence": { "blockNumber": 133636220, "simOk": true, "gasEstimate": "46145", "feeBnb": "0.000002" },
  "task_id": "t-123"
}
```

## Run it locally

```bash
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET (test value is fine locally)
node server.js          # listens on :3000
npm test                # replays preflight + screen cases against live BSC RPC
```

`npm test` runs 15 checks against real BSC RPC, including: preflight + signed
response, unsigned request rejected, plain transfer → `APPROVE`, unlimited
approve → `REJECT`, finite approve → `REVIEW`, an already-claimed free slot →
`REJECT` with the chain's own `free taken` reason, and a transfer above the
wallet balance → `REJECT` (`insufficient funds`).

## Deploy (Vercel, free tier)

1. Push this repo to GitHub (public).
2. In Vercel: **Add New → Project → Import** the repo. Framework preset: Other.
3. Environment variable: `AGENT_GAMES_HMAC_SECRET` = the secret from the
   Agent Games dashboard (**My Agents → Rotate Secret**, shown once).
4. Deploy. Your endpoint is `https://<project>.vercel.app/api/agent`.
   The demo page is at the project root (`https://<project>.vercel.app/`)
   and the public demo API at `POST /api/demo`.
5. In the Agent Games dashboard, register the agent with the full handler
   path (`…/api/agent`, not just the domain) and run **preflight** — it must
   pass before the platform marks the agent active.
6. Alternative: run `server.js` anywhere Node runs (Render, Fly.io, a VPS)
   with the same env var; the endpoint is then `https://<host>/agent`.

Notes: Vercel serverless functions sleep between requests but wake in ~1s,
well inside the platform's 60s deadline. `vercel.json` sets `maxDuration: 60`
for both functions. The HMAC secret is read from the environment only — never
commit it; `.env` is gitignored.

## What it can and cannot do

- **Can:** screen any BSC (chain 56) transaction before signing; explain
  approvals, transfers, operator grants, free claims, and plain transfers in
  one line; catch reverts and insufficient funds before gas is spent.
- **Cannot:** screen other chains; know the *intent* behind a transaction
  (a `REVIEW` is the agent saying "here is exactly what happens — you
  decide"); verify a contract beyond Sourcify's records; guarantee a
  verified contract is honest — verification proves the code matches the
  source, not that the source is safe.

## zkVerify (optional plus) — honest note

No Groth16 proof is claimed for the screening computation itself: generating
a circuit for an RPC simulation is out of scope for this build. What *is*
checkable today, by design: every verdict is deterministic from public data
and cites the block number, the simulation result, and the gas estimate, so
any reviewer can re-run the identical `eth_call` against a BSC node and
confirm the verdict. That is the checkable claim. A natural next step is
zkTLS: turn the HTTPS/RPC responses the verdict relied on into a
zkVerify-checkable claim without revealing the full payload.

## Security

- No private keys, seed phrases, or wallet credentials anywhere in this repo
  or in the agent's memory. The agent only ever *reads* the chain.
- The HMAC secret is the only secret, loaded from the environment.
- Inbound HMAC is verified over the **raw** request body before any JSON
  parsing; responses are signed over the raw response body.
- All screening failures fail closed to `REJECT` — never to `APPROVE`.

## Why this agent, why this owner

The owner runs a Binance Agentic Wallet (`vinxs.ai`) and has approved dozens
of on-chain transactions through it — free mints, listings, claims. Every
rule in the verdict policy comes from a real mistake or near-miss in that
history: an unlimited approval that should never have been signed, a free
claim that reverted because the slot was already taken, a transfer that
exceeded the wallet balance. VinGuard is that hard-won checklist, running as
an endpoint instead of a memory.
