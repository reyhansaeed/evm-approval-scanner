#!/usr/bin/env python3
"""evm-approval-scanner — find risky ERC-20 token approvals on any EVM wallet.

Unlimited (or oversized) token approvals are the #1 wallet-drainer vector: once
you approve a malicious/compromised contract, it can move that token forever.
This tool scans a wallet's on-chain Approval events and flags the dangerous ones.

Pure standard library — no web3.py, no API key. Talks JSON-RPC to any public node.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

# keccak256("Approval(address,address,uint256)") — hardcoded so we need no hashing dep
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
ALLOWANCE_SELECTOR = "0xdd62ed3e"  # allowance(address,address)
MAX_UINT = (1 << 256) - 1
UNLIMITED_THRESHOLD = 1 << 255  # anything above this is "effectively unlimited"

# drpc.org public endpoints allow anonymous eth_getLogs (many public RPCs block it).
DEFAULT_RPCS = {
    "ethereum": "https://eth.drpc.org",
    "polygon": "https://polygon.drpc.org",
    "bsc": "https://bsc.drpc.org",
    "arbitrum": "https://arbitrum.drpc.org",
    "base": "https://base.drpc.org",
    "optimism": "https://optimism.drpc.org",
}


class RpcError(Exception):
    pass


def rpc(url: str, method: str, params: list) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (compatible; evm-approval-scanner/1.0)",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RpcError(f"HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise RpcError(f"connection failed: {e.reason}")
    if "error" in data:
        raise RpcError(data["error"].get("message", str(data["error"])))
    return data["result"]


def pad_topic(address: str) -> str:
    return "0x" + address.lower().replace("0x", "").rjust(64, "0")


def to_addr(topic: str) -> str:
    return "0x" + topic[-40:]


@dataclass
class Approval:
    token: str
    spender: str
    allowance: int
    block: int

    @property
    def risk(self) -> str:
        if self.allowance == 0:
            return "safe (revoked)"
        if self.allowance >= UNLIMITED_THRESHOLD:
            return "UNLIMITED"
        return "limited"


def scan(rpc_url: str, owner: str, from_block: int, chunk: int) -> list[Approval]:
    latest = int(rpc(rpc_url, "eth_blockNumber", []), 16)
    seen: dict[tuple[str, str], Approval] = {}
    start = from_block
    successes = 0
    while start <= latest:
        end = min(start + chunk - 1, latest)
        try:
            logs = rpc(rpc_url, "eth_getLogs", [{
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [APPROVAL_TOPIC, pad_topic(owner)],
            }])
            successes += 1
        except RpcError as e:
            msg = str(e).lower()
            # Block-range / response-size cap: shrink the window and retry it.
            # (Many nodes signal this as HTTP 400/413 with no JSON body.)
            if chunk > 1000 and any(k in msg for k in
                                    ("range", "limit", "large", "many", "size", "bad request",
                                     "400", "413", "-32005", "-32602", "-32600")):
                chunk = max(1000, chunk // 4)
                continue
            # RPC refuses eth_getLogs entirely (and never worked): bail out with guidance.
            if successes == 0 and any(k in msg for k in
                                      ("403", "401", "429", "forbidden", "unauthor", "not support", "disabled")):
                raise RpcError(
                    f"this RPC won't serve eth_getLogs anonymously ({e}). "
                    "Pass --rpc with a node that supports eth_getLogs "
                    "(e.g. your own, Alchemy, Infura or QuickNode).")
            print(f"  ! skipped {start}-{end}: {e}", file=sys.stderr)
            start = end + 1
            continue
        for lg in logs:
            token = lg["address"]
            spender = to_addr(lg["topics"][2])
            blk = int(lg["blockNumber"], 16)
            key = (token.lower(), spender.lower())
            # Keep only the most recent approval per (token, spender) pair.
            if key not in seen or blk >= seen[key].block:
                seen[key] = Approval(token, spender, 0, blk)
        start = end + 1
    # Resolve the *current* on-chain allowance for each pair (past events can be stale).
    for ap in seen.values():
        call = ALLOWANCE_SELECTOR + pad_topic(owner)[2:] + pad_topic(ap.spender)[2:]
        try:
            res = rpc(rpc_url, "eth_call", [{"to": ap.token, "data": call}, "latest"])
            ap.allowance = int(res, 16) if res and res != "0x" else 0
        except RpcError:
            ap.allowance = -1
    return [a for a in seen.values() if a.allowance != 0]


def main() -> int:
    p = argparse.ArgumentParser(description="Scan an EVM wallet for risky ERC-20 approvals.")
    p.add_argument("address", help="wallet address (0x...)")
    p.add_argument("-c", "--chain", default="ethereum",
                   help=f"chain preset ({', '.join(DEFAULT_RPCS)}) or use --rpc")
    p.add_argument("--rpc", help="custom JSON-RPC URL (overrides --chain)")
    p.add_argument("--from-block", type=int, default=0, help="start block (default 0)")
    p.add_argument("--chunk", type=int, default=3000,
                   help="block range per request (auto-shrinks if the node caps it)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args()

    rpc_url = args.rpc or DEFAULT_RPCS.get(args.chain)
    if not rpc_url:
        p.error(f"unknown chain '{args.chain}'. Choices: {', '.join(DEFAULT_RPCS)}")

    if not (args.address.startswith("0x") and len(args.address) == 42):
        p.error("address must be a 42-char 0x-prefixed hex string")

    print(f"Scanning {args.address} on {args.chain} ...", file=sys.stderr)
    try:
        approvals = sorted(scan(rpc_url, args.address, args.from_block, args.chunk),
                           key=lambda a: (a.risk != "UNLIMITED", -a.block))
    except RpcError as e:
        print(f"\n✗ {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([{
            "token": a.token, "spender": a.spender,
            "allowance": a.allowance, "risk": a.risk, "block": a.block,
        } for a in approvals], indent=2))
        return 0

    if not approvals:
        print("\n✅ No active approvals found. Clean wallet.")
        return 0

    risky = [a for a in approvals if a.risk == "UNLIMITED"]
    print(f"\nFound {len(approvals)} active approval(s), {len(risky)} UNLIMITED:\n")
    print(f"  {'TOKEN':42}  {'SPENDER':42}  RISK")
    print(f"  {'-'*42}  {'-'*42}  ----")
    for a in approvals:
        mark = "🔴" if a.risk == "UNLIMITED" else "🟡"
        print(f"  {a.token:42}  {a.spender:42}  {mark} {a.risk}")
    if risky:
        print(f"\n⚠️  {len(risky)} unlimited approval(s). Revoke the ones you don't recognise")
        print("   at https://revoke.cash or by calling approve(spender, 0).")
    return 1 if risky else 0


if __name__ == "__main__":
    raise SystemExit(main())
