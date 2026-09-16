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

This package is a thin stdio/HTTP bridge: it forwards JSON-RPC to the hosted
verifier at `verify.code402.dev` and quarantines every diagnostic to stderr, so
stdout carries only clean JSON-RPC 2.0 frames (a hard requirement for Docker and
desktop MCP runners). Point it elsewhere with `CODE402_VERIFY_URL`.

Verification is pure recomputation over public data — the same operation any
agent can run offline against its own receipts.

## License

MIT
