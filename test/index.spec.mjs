import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";

// Golden vector matches hcrb/packages/core/test/receipt.test.ts — byte-exact
// with the live code402 rail. Key is synthetic and test-only.
const TEST_KEY_BYTES = new Uint8Array(32).fill(0x11);
const TEST_SIGNER = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
const CORE = {
  v: "XDR-1", tool: "iban-check", tool_version: "1.0.0",
  input_hash: "0x" + "11".repeat(32), output_hash: "0x" + "22".repeat(32),
  payer: "0x" + "aa".repeat(20), recipient: "0x" + "bb".repeat(20),
  amount: "5000", nonce: "0x" + "33".repeat(32), ts: 1700000000, tier: "paid",
};
const CANON = [CORE.v, CORE.tool, CORE.tool_version, CORE.input_hash, CORE.output_hash, CORE.payer, CORE.recipient, CORE.amount, CORE.nonce, CORE.ts, CORE.tier].join("|");
const bh = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
function sign(canon) {
  const sig = secp256k1.sign(keccak_256(new TextEncoder().encode(canon)), TEST_KEY_BYTES);
  return "0x" + bh(sig.toCompactRawBytes()) + (sig.recovery + 27).toString(16).padStart(2, "0");
}
const SIGNED = { ...CORE, signature: sign(CANON), signer: TEST_SIGNER };

let proc;
let msgId = 0;
const pending = new Map();
let buffer = "";

function rpc(method, params) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => reject(new Error("timeout")), 5000);
  });
}

beforeAll(async () => {
  proc = spawn(process.execPath, ["index.mjs"], { cwd: fileURLToPath(new URL("..", import.meta.url)) });
  proc.stdout.on("data", (d) => {
    buffer += d.toString();
    let i;
    while ((i = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
      if (!line.trim()) continue;
      const m = JSON.parse(line);
      if (m.id && pending.has(m.id)) { pending.get(m.id).resolve(m); pending.delete(m.id); }
    }
  });
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
});

afterAll(() => proc?.kill());

describe("@code402/verify-mcp (local-first)", () => {
  it("lists x402_verify", async () => {
    const res = await rpc("tools/list", {});
    expect(res.result.tools.map((t) => t.name)).toEqual(["x402_verify"]);
  });

  it("verifies a correctly signed receipt locally (valid:true, signer recovered)", async () => {
    const res = await rpc("tools/call", { name: "x402_verify", arguments: { raw_receipt: JSON.stringify(SIGNED) } });
    const out = JSON.parse(res.result.content[0].text);
    expect(out.valid).toBe(true);
    expect(out.signer_recovered).toBe(TEST_SIGNER);
    expect(out.scope).toContain("not proof of settlement");
  });

  it("rejects a tampered receipt (valid:false, not an error)", async () => {
    const res = await rpc("tools/call", { name: "x402_verify", arguments: { raw_receipt: JSON.stringify({ ...SIGNED, amount: "5001" }) } });
    expect(JSON.parse(res.result.content[0].text).valid).toBe(false);
  });

  it("rejects malformed JSON in raw_receipt with an explanatory error", async () => {
    const res = await rpc("tools/call", { name: "x402_verify", arguments: { raw_receipt: "{not json" } });
    const out = JSON.parse(res.result.content[0].text);
    expect(out.valid).toBe(false);
    expect(out.error).toContain("not valid JSON");
  });
});
