import { describe, it, expect } from "vitest";
import type { ReceiptDocumentVerification } from "@motebit/state-export-client";
import {
  assessVerdict,
  classifyRpc,
  observeSignatureScans,
  scansComplete,
  PROXY_LABEL,
  type ChainEvidence,
} from "../assess.js";

const v = (over: Partial<ReceiptDocumentVerification> = {}): ReceiptDocumentVerification => ({
  integrity: true,
  binding: "integrity-only",
  ...over,
});
const INDEPENDENT_COMPLETE: ChainEvidence = { source: "independent", revocationScanComplete: true };
const INDEPENDENT_TRUNCATED: ChainEvidence = {
  source: "independent",
  revocationScanComplete: false,
};
const PROXY_COMPLETE: ChainEvidence = { source: "operator-proxy", revocationScanComplete: true };

describe("classifyRpc", () => {
  it("operator hosts and garbage are the proxy; anything else is independent", () => {
    expect(classifyRpc("https://api.motebit.com/v1/solana-rpc")).toBe("operator-proxy");
    expect(classifyRpc("https://motebit.com/x")).toBe("operator-proxy");
    expect(classifyRpc("https://rpc.receipt.computer/")).toBe("operator-proxy");
    expect(classifyRpc("not a url")).toBe("operator-proxy");
    expect(classifyRpc("https://notmotebit.com/")).toBe("independent");
    expect(classifyRpc("http://localhost:8899")).toBe("independent");
  });
});

describe("assessVerdict", () => {
  it("receipt-alone sovereign is always a key commitment, whatever the evidence", () => {
    for (const ev of [undefined, INDEPENDENT_COMPLETE, PROXY_COMPLETE]) {
      expect(assessVerdict(v({ binding: "sovereign" }), ev).binding).toBe("key-commitment");
    }
  });

  it("nested sovereign delegations are key commitments too", () => {
    const d = assessVerdict(v({ delegations: [v({ binding: "sovereign" })] }));
    expect(d.delegations?.[0]?.binding).toBe("key-commitment");
  });

  it("anchored stands only on independent evidence; otherwise pinned + proxy flag", () => {
    const a = assessVerdict(v({ binding: "anchored", anchorTxHash: "TX" }), INDEPENDENT_COMPLETE);
    expect(a.binding).toBe("anchored");
    expect(a.anchorTxHash).toBe("TX");
    for (const ev of [undefined, PROXY_COMPLETE]) {
      const p = assessVerdict(v({ binding: "anchored", anchorTxHash: "TX" }), ev);
      expect(p.binding).toBe("pinned");
      expect(p.anchorViaProxy).toBe(true);
      expect(p.anchorTxHash).toBeUndefined();
    }
  });

  it("revocation ✓ only on a complete independent scan", () => {
    for (const r of ["not_revoked", "revoked_after_signing"] as const) {
      expect(assessVerdict(v({ revocation: r }), INDEPENDENT_COMPLETE).revocation).toBe(r);
      const trunc = assessVerdict(v({ revocation: r }), INDEPENDENT_TRUNCATED);
      expect(trunc.revocation).toBe("not_established");
      expect(trunc.revocationNote).toContain("200-signature page limit");
      const proxy = assessVerdict(v({ revocation: r }), PROXY_COMPLETE);
      expect(proxy.revocation).toBe("not_established");
      expect(proxy.revocationNote).toContain(PROXY_LABEL);
      expect(assessVerdict(v({ revocation: r })).revocation).toBe("not_established");
    }
    const failed = assessVerdict(
      v({ revocation: "unknown", revocationDetail: "HTTP 503" }),
      INDEPENDENT_COMPLETE,
    );
    expect(failed.revocation).toBe("not_established");
    expect(failed.revocationNote).toContain("HTTP 503");
  });

  it("a found revocation stays REVOKED from any source, labelled by source", () => {
    const r = assessVerdict(
      v({ binding: "revoked", revocation: "revoked", revokedAt: 5 }),
      PROXY_COMPLETE,
    );
    expect(r.binding).toBe("revoked");
    expect(r.revocation).toBe("revoked");
    expect(r.chainSource).toBe("operator-proxy");
  });

  it("offline views pass through without chain fields", () => {
    const o = assessVerdict(v({ motebitId: "m", taskId: "t", signerDid: "did:key:z" }));
    expect(o).toEqual({
      integrity: true,
      binding: "integrity-only",
      motebitId: "m",
      taskId: "t",
      signerDid: "did:key:z",
    });
  });
});

describe("observeSignatureScans / scansComplete", () => {
  const rpcBody = (limit: number) =>
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getSignaturesForAddress",
      params: ["addr", { limit }],
    });
  const respond =
    (n: number, status = 200): typeof fetch =>
    async () =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: new Array(n).fill({}) }), {
        status,
      });

  it("a scan that returns fewer than the limit is complete", async () => {
    const o = observeSignatureScans(respond(3));
    const res = await o.fetch("https://rpc", { method: "POST", body: rpcBody(200) });
    expect(((await res.json()) as { result: unknown[] }).result).toHaveLength(3);
    expect(o.scans).toEqual([{ ok: true, limit: 200, returned: 3 }]);
    expect(scansComplete(o.scans)).toBe(true);
  });

  it("a scan that hits the limit, fails, or throws is not complete; no scan is not complete", async () => {
    const full = observeSignatureScans(respond(200));
    await full.fetch("https://rpc", { method: "POST", body: rpcBody(200) });
    expect(scansComplete(full.scans)).toBe(false);

    const http = observeSignatureScans(respond(0, 503));
    await http.fetch("https://rpc", { method: "POST", body: rpcBody(200) });
    expect(scansComplete(http.scans)).toBe(false);

    const thrown = observeSignatureScans(async () => {
      throw new TypeError("down");
    });
    await expect(
      thrown.fetch("https://rpc", { method: "POST", body: rpcBody(200) }),
    ).rejects.toThrow("down");
    expect(thrown.scans).toEqual([{ ok: false, limit: 200 }]);
    expect(scansComplete(thrown.scans)).toBe(false);

    const rpcError = observeSignatureScans(
      async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: "x" } })),
    );
    await rpcError.fetch("https://rpc", { method: "POST", body: rpcBody(200) });
    expect(scansComplete(rpcError.scans)).toBe(false);

    expect(scansComplete([])).toBe(false);
  });

  it("non-scan requests are passed through and not recorded", async () => {
    const o = observeSignatureScans(respond(1));
    await o.fetch("https://relay/x");
    expect(o.scans).toEqual([]);
  });
});
