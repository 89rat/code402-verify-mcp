/**
 * code402-verify — the standalone XDR-1 receipt verifier.
 *
 * Extracted 2026-09-23 from the monolith (code402-edge-v2) to kill its cold start:
 * the verification is ~200 lines + noble crypto; cold init is milliseconds, not the
 * monolith's 11.3s. The logic is byte-identical to the rail's verifier (canon,
 * keccak_256, secp256k1 recovery, compare-to-declared-signer) — one verification
 * implementation, now in the small package that owns the vanity host.
 *
 * Surfaces:
 *   GET  / or /health        → service descriptor
 *   POST / or /mcp           → MCP JSON-RPC (initialize, tools/list, tools/call x402_verify)
 *   POST /v1/receipt/verify  → REST verify (same logic)
 */
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const SERVICE_VERSION = "1.3.0";
const te = (s: string) => new TextEncoder().encode(s);
const bh = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const hb = (h: string) => {
  h = h.replace(/^0x/, "");
  const o = new Uint8Array(h.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
  return o;
};

interface ReceiptCore {
  v: string;
  tool: string;
  tool_version: string;
  input_hash: string;
  output_hash: string;
  payer: string;
  recipient: string;
  amount: string;
  nonce: string;
  ts: number;
  tier: string;
  successor?: string;
  stream_state?: string;
}

/** The XDR-1 canonical form: 11 base fields, plus successor/stream_state when present. */
const canon = (r: ReceiptCore) => {
  const parts = [r.v, r.tool, r.tool_version, r.input_hash, r.output_hash, r.payer, r.recipient, r.amount, r.nonce, String(r.ts), r.tier];
  if (r.successor || r.stream_state) {
    parts.push(r.successor || "", r.stream_state || "active");
  }
  return parts.join("|");
};

function recover(dig: Uint8Array, sigHex: string): string | null {
  try {
    const s = hb(sigHex);
    if (s.length !== 65) return null;
    let v = s[64];
    if (v >= 27) v -= 27;
    if (v !== 0 && v !== 1) return null;
    const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v);
    return "0x" + bh(keccak_256(sig.recoverPublicKey(dig).toRawBytes(false).slice(1)).slice(12));
  } catch {
    return null;
  }
}

const REQUIRED_FIELDS = ["v", "tool", "tool_version", "input_hash", "output_hash", "payer", "recipient", "amount", "nonce", "ts", "tier"];

interface VerifyOutcome {
  valid: boolean;
  reason?: string;
  signer_recovered?: string | null;
  declared_signer?: string | null;
  digest?: string;
  canonical?: string;
  scope: string;
}

function verifyReceiptPayload(r: any): VerifyOutcome {
  if (!r || typeof r !== "object" || !REQUIRED_FIELDS.every((f) => r[f] !== undefined) || typeof r.signature !== "string") {
    return { valid: false, reason: "receipt must carry " + REQUIRED_FIELDS.join(", ") + " and a signature", scope: "input validation" };
  }
  try {
    const digest = keccak_256(te(canon(r)));
    const recovered = recover(digest, r.signature);
    const valid = recovered !== null && r.signer !== undefined && recovered.toLowerCase() === String(r.signer).toLowerCase();
    return { valid, signer_recovered: recovered, declared_signer: r.signer ?? null, digest: "0x" + bh(digest), canonical: canon(r), scope: "signature + digest verification only — not proof of settlement" };
  } catch (e: any) {
    return { valid: false, reason: String(e?.message || e), scope: "verification failed" };
  }
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, accept, authorization, x-payment, payment-signature, payment-required, mcp-session-id, mcp-protocol-version",
};
const j = (o: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", ...CORS, ...extra } });

const DESCRIPTOR = {
  service: "code402-verify",
  version: SERVICE_VERSION,
  transport: "MCP over JSON-RPC 2.0 (Streamable HTTP): POST to this URL",
  tool: {
    name: "x402_verify",
    input: { raw_receipt: "string — the full signed XDR-1 receipt JSON", settlement_asset: "string? — default USDC" },
  },
  rest: "POST /v1/receipt/verify with { receipt: <XDR-1 receipt> } or the receipt object directly",
  free: true,
  verifies: "XDR-1 receipts: keccak over the canonical receipt, secp256k1 signer recovery, compared to the declared signer",
  machine_surface: "https://hcrb.in",
  human_surface: "https://code402.dev",
};

function mcpReply(id: unknown, result: unknown) {
  return j({ jsonrpc: "2.0", id: id ?? null, result }, 200);
}
function mcpError(id: unknown, code: number, message: string) {
  return j({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }, 200);
}

async function handleMcp(req: Request): Promise<Response> {
  let rpc: any;
  try {
    rpc = await req.json();
  } catch {
    return mcpError(null, -32700, "Parse error");
  }
  const id = rpc?.id ?? null;
  if (rpc?.method === "initialize") {
    return mcpReply(id, {
      protocolVersion: typeof rpc?.params?.protocolVersion === "string" ? rpc.params.protocolVersion : "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "code402-verify", version: SERVICE_VERSION },
    });
  }
  if (rpc?.method === "notifications/initialized" || rpc?.method === "notifications/cancelled") {
    return new Response(null, { status: 202, headers: CORS });
  }
  if (rpc?.method === "ping") return mcpReply(id, {});
  if (rpc?.method === "tools/list") {
    return mcpReply(id, {
      tools: [{
        name: "x402_verify",
        description: "verify_receipt(raw_receipt:str!,settlement_asset:str?)->valid:bool,payer:str",
        inputSchema: {
          type: "object",
          properties: { raw_receipt: { type: "string" }, settlement_asset: { type: "string" } },
          required: ["raw_receipt"],
        },
      }],
    });
  }
  if (rpc?.method === "tools/call") {
    if (rpc?.params?.name !== "x402_verify") {
      return mcpError(id, -32601, "Tool not found: " + String(rpc?.params?.name ?? ""));
    }
    const raw = rpc?.params?.arguments?.raw_receipt;
    const invalid = (error: string) =>
      mcpReply(id, { isError: false, content: [{ type: "text", text: JSON.stringify({ valid: false, error }) }] });
    if (typeof raw !== "string" || !raw.trim()) return invalid("raw_receipt is required (the full signed receipt JSON)");
    let r: any;
    try {
      r = JSON.parse(raw);
    } catch {
      return invalid("raw_receipt is not valid JSON");
    }
    const out = verifyReceiptPayload(r);
    const receiptHash = typeof r.receipt_hash === "string" ? r.receipt_hash : null;
    const settlementAsset = typeof rpc?.params?.arguments?.settlement_asset === "string" ? rpc.params.arguments.settlement_asset : "USDC";
    return mcpReply(id, {
      isError: false,
      content: [{
        type: "text",
        text: JSON.stringify({
          valid: out.valid,
          payer: typeof r.payer === "string" ? r.payer : null,
          amount: typeof r.amount === "string" ? r.amount : null,
          tool: typeof r.tool === "string" ? r.tool : null,
          receipt_hash: receiptHash,
          settlement_asset: settlementAsset,
          reason: out.valid ? undefined : out.reason,
          scope: out.scope,
          _meta: {
            verified_by: "code402",
            network: "base-mainnet",
            signer: r.signer ?? null,
            signer_recovered: out.signer_recovered ?? null,
            attestation_url: receiptHash ? "https://hcrb.in/audit/" + receiptHash : null,
          },
        }),
      }],
    });
  }
  return mcpError(id, -32601, "Method not supported: " + String(rpc?.method));
}

export default {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    if (req.method === "GET") {
      return j({ ...DESCRIPTOR, uptime_hint: "dedicated worker — no monolith cold start" }, 200, { "cache-control": "public, max-age=300" });
    }

    if (req.method === "POST" && (url.pathname === "/" || url.pathname === "/mcp")) {
      return handleMcp(req);
    }

    if (req.method === "POST" && url.pathname === "/v1/receipt/verify") {
      let b: any;
      try {
        b = await req.json();
      } catch {
        return j({ error: { code: "BAD_JSON", message: "body must be JSON: { receipt } or the receipt object" } }, 400);
      }
      const r = b?.receipt ?? b;
      return j(verifyReceiptPayload(r), 200);
    }

    return j({ error: { code: "NOT_FOUND", message: "POST /mcp for MCP, POST /v1/receipt/verify for REST, GET / for the descriptor" } }, 404);
  },
};
