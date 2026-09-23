import { describe, it, expect } from "vitest";
import worker from "../src/index.ts";

/**
 * Parity with the rail's verifier, pinned against a real receipt minted by the
 * deployed worker (2026-09-15, stream_state extension exercised).
 */
const LIVE_RECEIPT = {
  v: "XDR-1", tool: "iban-check", tool_version: "1.0.0",
  input_hash: "0xab7d4ba329e033c4e5d6255c2d728a3ac138727087128fd58edb6c78e177e512",
  output_hash: "0x9dd8f9763c3cb81a39ce2f7a0694f01bc9c9c1e2c9a9d259d96a0bc27a1627b2",
  payer: "free:2405:201:c01a:e8d5:49f4:1224:c6c6:898a",
  recipient: "0xc59c85e661d34084a7769f955d17fd38254a6235",
  amount: "0",
  nonce: "0xc082c1a5d167e3d0ea872fa8dc297e29c60b4f54fdce96bcaa684cb611b9f4f4",
  ts: 1789479834, tier: "free", stream_state: "active",
  signature: "0xc36c461d6873d5fce28618fe2bf338b8dbc957961946f6b578cbbcc59d70f6c20298e541542163c5cae65dcace3f9b72f6b0ccd26415c214ac5a9455351815681b",
  signer: "0xa036e2e3e19c6d02f30b3a9eb0acd057e6d9a5c8",
};

const call = (path: string, init?: RequestInit) => worker.fetch(new Request("https://verify.code402.dev" + path, init));

describe("standalone verifier", () => {
  it("GET / serves the descriptor", async () => {
    const res = await call("/");
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.service).toBe("code402-verify");
    expect(body.tool.name).toBe("x402_verify");
  });

  it("MCP initialize + tools/list", async () => {
    const init = await call("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) });
    expect((await init.json() as any).result.serverInfo.name).toBe("code402-verify");
    const list = await call("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) });
    expect((await list.json() as any).result.tools[0].name).toBe("x402_verify");
  });

  it("real receipt verifies valid via REST", async () => {
    const res = await call("/v1/receipt/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt: LIVE_RECEIPT }) });
    const body = (await res.json()) as any;
    expect(body.valid).toBe(true);
    expect(body.signer_recovered).toBe(LIVE_RECEIPT.signer);
  });

  it("real receipt verifies valid via MCP tools/call", async () => {
    const res = await call("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "x402_verify", arguments: { raw_receipt: JSON.stringify(LIVE_RECEIPT) } } }) });
    const body = (await res.json()) as any;
    const payload = JSON.parse(body.result.content[0].text);
    expect(payload.valid).toBe(true);
    expect(payload._meta.signer_recovered).toBe(LIVE_RECEIPT.signer);
    expect(payload._meta.attestation_url).toBeNull(); // no receipt_hash on this fixture
  });

  it("tampered signature fails (never crashes)", async () => {
    const bad = { ...LIVE_RECEIPT, signature: "0x" + "ab".repeat(64) + "1b" };
    const res = await call("/v1/receipt/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt: bad }) });
    const body = (await res.json()) as any;
    expect(body.valid).toBe(false);
  });

  it("missing fields get the input-validation refusal", async () => {
    const res = await call("/v1/receipt/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt: { v: "XDR-1" } }) });
    const body = (await res.json()) as any;
    expect(body.valid).toBe(false);
    expect(body.scope).toBe("input validation");
  });
});
