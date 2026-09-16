#!/usr/bin/env node
/**
 * @code402/verify-mcp — MCP server for verifying code402 XDR-1 receipts.
 *
 * Transports: stdio (this entry) proxies to the hosted verifier at
 * https://verify.code402.dev/ (MCP over JSON-RPC 2.0, Streamable HTTP).
 * Verification is deterministic and free: keccak-256 over the canonical receipt,
 * secp256k1 public-key recovery, compared to the declared signer. The hosted
 * endpoint holds no keys and performs no settlement — it is pure recomputation.
 *
 * Stdout carries ONLY single-line JSON-RPC 2.0 frames; every diagnostic goes to
 * stderr, so Docker and desktop MCP runners never see a corrupted stream.
 */
import { createInterface } from "node:readline";

const REMOTE = process.env.CODE402_VERIFY_URL || "https://verify.code402.dev/";

function err(msg) {
  process.stderr.write(`[code402-verify-mcp] ${msg}\n`);
}

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
  description: "verify_receipt(raw_receipt:str!,settlement_asset:str?)->valid:bool,payer:str",
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
          serverInfo: { name: "code402-verify", version: "0.1.0" },
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
err(`code402-verify-mcp ready -> ${REMOTE}`);
