#!/usr/bin/env node
/**
 * @code402/verify-mcp — MCP server for verifying code402 XDR-1 receipts.
 *
 * LOCAL-FIRST (since 0.2.0): verification runs entirely on your machine —
 * keccak-256 over the canonical receipt, secp256k1 public-key recovery,
 * compared to the declared signer. No network calls, no keys held, no
 * settlement performed. Set CODE402_VERIFY_URL to proxy to the hosted verifier
 * (https://verify.code402.dev/) instead — the answer is identical by
 * construction (deterministic recomputation over public data).
 *
 * Stdout carries ONLY single-line JSON-RPC 2.0 frames; every diagnostic goes to
 * stderr, so Docker and desktop MCP runners never see a corrupted stream.
 *
 * Wire format is byte-exact with the live code402 rail (https://hcrb.in);
 * golden vectors pinned in test/.
 */
import { createInterface } from "node:readline";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

const REMOTE = process.env.CODE402_VERIFY_URL || null; // opt-in only
const VERSION = "0.2.0";

function err(msg) {
  process.stderr.write(`[code402-verify-mcp] ${msg}\n`);
}

// ---------- local XDR-1 verification (the default path) ----------

const bh = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
function hb(h) {
  const s = typeof h === "string" && h.startsWith("0x") ? h.slice(2) : h;
  if (typeof s !== "string" || s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Deployed-format fact: the successor/stream_state slot is appended whenever
// either field is set, and live receipts always carry it (…|tier||active).
function canonReceipt(r) {
  const parts = [r.v, r.tool, r.tool_version, r.input_hash, r.output_hash, r.payer, r.recipient, r.amount, r.nonce, r.ts, r.tier];
  if (r.successor || r.stream_state) parts.push(r.successor || "", r.stream_state || "active");
  return parts.join("|");
}

function recoverSigner(digest, sigHex) {
  try {
    const s = hb(sigHex);
    if (s === null || s.length !== 65) return null;
    let v = s[64];
    if (v >= 27) v -= 27;
    if (v !== 0 && v !== 1) return null;
    const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v);
    return "0x" + bh(keccak_256(sig.recoverPublicKey(digest).toRawBytes(false).slice(1)).slice(12));
  } catch { return null; }
}

function verifyLocal(receipt) {
  if (!receipt || typeof receipt !== "object") return { valid: false, error: "raw_receipt must parse to an object" };
  const sigBytes = hb(receipt.signature ?? "");
  if (sigBytes === null || sigBytes.length !== 65) return { valid: false, error: "signature must be 65 bytes of hex (0x + r‖s + v)" };
  const canonical = canonReceipt(receipt);
  const digestBytes = keccak_256(new TextEncoder().encode(canonical));
  const recovered = recoverSigner(digestBytes, receipt.signature);
  const declared = typeof receipt.signer === "string" ? receipt.signer.toLowerCase() : null;
  return {
    valid: recovered !== null && recovered === declared,
    payer: receipt.payer ?? null,
    amount: receipt.amount ?? null,
    receipt_hash: "0x" + bh(digestBytes),
    signer_recovered: recovered,
    declared_signer: declared,
    scope: "signature + digest verification only — not proof of settlement",
    _meta: { verified_by: "code402-verify-mcp (local, offline)", version: VERSION },
  };
}

// ---------- optional hosted proxy (CODE402_VERIFY_URL set) ----------

async function callRemote(message) {
  const res = await fetch(REMOTE, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(message),
  });
  if (res.status === 202) return undefined; // notification acknowledged
  const text = await res.text();
  if (!res.ok) throw new Error(`verifier responded ${res.status}: ${text.slice(0, 200)}`);
  return text.trim() ? JSON.parse(text) : undefined;
}

function send(frame) {
  process.stdout.write(JSON.stringify(frame) + "\n");
}

const TOOL = {
  name: "x402_verify",
  description: "verify_receipt(raw_receipt:str!,settlement_asset:str?)->valid:bool,payer:str — offline by default (no network); set CODE402_VERIFY_URL to use the hosted verifier",
  inputSchema: {
    type: "object",
    properties: { raw_receipt: { type: "string" }, settlement_asset: { type: "string" } },
    required: ["raw_receipt"],
  },
};

const rl = createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (e) {
    err(`malformed JSON-RPC frame: ${e.message}`);
    return;
  }
  const { id, method, params } = msg;

  const respond = (result) => send({ jsonrpc: "2.0", id, result });
  const fail = (code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

  (async () => {
    switch (method) {
      case "initialize":
        respond({
          protocolVersion: typeof params?.protocolVersion === "string" ? params.protocolVersion : "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "code402-verify", version: VERSION },
        });
        return;
      case "notifications/initialized":
      case "notifications/cancelled":
        return; // notifications get no response over stdio
      case "tools/list":
        respond({ tools: [TOOL] });
        return;
      case "tools/call": {
        if (params?.name !== "x402_verify") {
          fail(-32601, `Tool not found: ${String(params?.name ?? "")}`);
          return;
        }
        if (!REMOTE) {
          let receipt;
          try { receipt = JSON.parse(String(params?.arguments?.raw_receipt ?? "")); }
          catch { respond({ isError: false, content: [{ type: "text", text: JSON.stringify({ valid: false, error: "raw_receipt is not valid JSON" }) }] }); return; }
          respond({ isError: false, content: [{ type: "text", text: JSON.stringify(verifyLocal(receipt)) }] });
          return;
        }
        try {
          const upstream = await callRemote({ jsonrpc: "2.0", id: 0, method: "tools/call", params });
          if (upstream?.error) {
            respond({ isError: true, content: [{ type: "text", text: JSON.stringify(upstream.error) }] });
            return;
          }
          respond(upstream.result);
        } catch (e) {
          err(`verify failed: ${e.message}`);
          respond({
            isError: false,
            content: [{ type: "text", text: JSON.stringify({ valid: false, error: `verifier unreachable: ${e.message}` }) }],
          });
        }
        return;
      }
      default:
        if (id === undefined || id === null) return; // unknown notification
        fail(-32601, `Method not supported: ${String(method)}`);
    }
  })().catch((e) => {
    err(`handler error: ${e.message}`);
    if (id !== undefined && id !== null) fail(-32603, "Internal error");
  });
});

rl.on("close", () => process.exit(0));
err(`code402-verify-mcp ready (${REMOTE ? "remote -> " + REMOTE : "local, offline"})`);
