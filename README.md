# @code402/verify-mcp

Verify [code402](https://code402.dev) **XDR-1 receipts** from any MCP client.
Every result a code402 endpoint returns carries a signed receipt; this server
checks the signature deterministically — keccak-256 over the canonical receipt,
secp256k1 public-key recovery, compared to the declared signer. Free, stateless,
no account: the verifier holds no keys and performs no settlement.

## Use with Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "code402-verify": {
      "command": "npx",
      "args": ["-y", "@code402/verify-mcp@latest"]
    }
  }
}
```

## Tool

`x402_verify` — verify one receipt:

```json
{ "raw_receipt": "<the full signed receipt JSON as a string>" }
```

Result:

```json
{
  "valid": true,
  "payer": "0x…",
  "amount": "5000",
  "receipt_hash": "0x…",
  "_meta": {
    "verified_by": "code402",
    "network": "base-mainnet",
    "signer": "0xa036…",
    "signer_recovered": "0xa036…",
    "attestation_url": "https://hcrb.in/audit/0x…"
  }
}
```

## How it works

**Local-first (since 0.2.0):** verification runs entirely on your machine —
keccak-256 over the canonical receipt, secp256k1 public-key recovery, compared
to the declared signer. No network calls, no keys held, nothing to trust but
the math. Set `CODE402_VERIFY_URL` to proxy to the hosted verifier at
`verify.code402.dev` instead — verdicts are identical by construction
(deterministic recomputation over public data).

Stdout carries only clean single-line JSON-RPC 2.0 frames; every diagnostic
goes to stderr (a hard requirement for Docker and desktop MCP runners).

Verification is pure recomputation over public data — the same operation any
agent can run offline against its own receipts.

## The hosted verifier's exact source (public)

`worker/` in this repo is the complete source of the hosted verifier at
`verify.code402.dev` (a dedicated Cloudflare worker, extracted from the rail
monolith 2026-09-23: 3ms startup vs the monolith's measured 11.3s cold start).
Same canon + keccak-256 + secp256k1 recovery, byte-identical verdicts — pinned
by `worker/test/index.spec.ts` against a real minted receipt. The public can
audit exactly what verifies their receipts.

## License

MIT
