<div align="center">

# evm-approval-scanner

**Find the risky ERC-20 token approvals that can drain your wallet.**

[![Python](https://img.shields.io/badge/python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Deps](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)

</div>

Unlimited token approvals are the number-one wallet-drainer vector. The moment you
approve a malicious or later-compromised contract, it can move that token out of your
wallet **forever** — no further signature needed. This tool reads your on-chain
`Approval` events, resolves the **current** allowance for each spender, and flags the
dangerous ones.

- 🔌 **Zero dependencies** — pure standard library, talks JSON-RPC to any public node
- 🔑 **No API key** — ships with public RPCs for 6 chains, or point it at your own
- 🔴 Flags **UNLIMITED** allowances so you know exactly what to revoke

## Install

```bash
git clone https://github.com/reyhansaeed/evm-approval-scanner
cd evm-approval-scanner
```
That's it — no `pip install`.

## Usage

```bash
# Scan a wallet on Ethereum
python scan.py 0xYourWallet

# Another chain
python scan.py 0xYourWallet --chain polygon

# Your own RPC + narrower block window (faster on rate-limited nodes)
python scan.py 0xYourWallet --rpc https://my-node --from-block 18000000

# Machine-readable
python scan.py 0xYourWallet --json
```

### Example output

```
Found 3 active approval(s), 1 UNLIMITED:

  TOKEN                                       SPENDER                                     RISK
  ------------------------------------------  ------------------------------------------  ----
  0xA0b8...eB48 (USDC)                         0xDef1...9552                               🔴 UNLIMITED
  0x6B17...1d0F (DAI)                          0x1111...1111                               🟡 limited

⚠️  1 unlimited approval(s). Revoke the ones you don't recognise
   at https://revoke.cash or by calling approve(spender, 0).
```

## How it works

1. `eth_getLogs` for the `Approval(owner, spender, value)` topic, filtered by your address
   (block range is auto-chunked and shrinks on rate-limit errors).
2. For every unique `(token, spender)` pair, `eth_call` → `allowance(owner, spender)` to
   get the **live** value (past events can be stale after partial spends/revokes).
3. Anything `≥ 2²⁵⁵` is reported as effectively unlimited.

## Notes & limits

- **For a full-history scan, use your own RPC** via `--rpc` — a free Alchemy / Infura /
  QuickNode key handles `eth_getLogs` far better than anonymous public nodes, which are
  rate-limited and cap the block range. The bundled public RPCs (drpc.org) work well for
  **recent** windows; set `--from-block` to bound the scan and the tool auto-shrinks the
  chunk to whatever the node accepts.
- If a node refuses `eth_getLogs` entirely, the tool tells you plainly (no stack trace)
  and suggests passing `--rpc`.
- Exit code is `1` when unlimited approvals are found — handy for scripts and alerts.
- Read-only. This tool **never** needs your private key and never sends a transaction.

## License

MIT © Rey ([@risingrey](https://x.com/risingrey))
