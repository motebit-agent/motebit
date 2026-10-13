import { describe, it, expect } from "vitest";
import { resultLabels } from "../labels.js";
import { PROXY_LABEL, type DisplayVerdict } from "../assess.js";

const ok = (over: Partial<DisplayVerdict> = {}): DisplayVerdict => ({
  integrity: true,
  binding: "integrity-only",
  ...over,
});

describe("resultLabels", () => {
  it("integrity-only NEVER claims verified identity", () => {
    const l = resultLabels(ok({ binding: "integrity-only" }));
    expect(l.tone).toBe("integrity");
    expect(l.headline).toContain("identity not anchored");
    expect(l.detail).toContain("not that the key belongs to this motebit");
    // The whole product requirement: do not say "verified" in the identity sense.
    expect(l.headline.toLowerCase()).not.toContain("identity anchored");
  });

  it("pinned claims identity (against supplied material), tone bound", () => {
    const l = resultLabels(ok({ binding: "pinned" }));
    expect(l.tone).toBe("bound");
    expect(l.headline).toContain("pinned");
    expect(l.detail).not.toContain(PROXY_LABEL);
  });

  it("pinned because the anchor was read only via the proxy says so", () => {
    const l = resultLabels(ok({ binding: "pinned", anchorViaProxy: true }));
    expect(l.grade).toBe("PINNED");
    expect(l.detail).toContain(PROXY_LABEL);
    expect(l.detail).toContain("anchored rung is not claimed");
  });

  it("a key commitment is lower assurance: integrity tone, never SOVEREIGN, never current authorization", () => {
    const l = resultLabels(ok({ binding: "key-commitment" }));
    expect(l.tone).toBe("integrity");
    expect(l.grade).toBe("KEY COMMITMENT");
    expect(`${l.grade} ${l.headline} ${l.detail}`).not.toMatch(/sovereign/i);
    expect(l.headline).toContain("current authorization not established");
    expect(l.detail).toContain(
      "identity commitment matches the motebit's original key; rotation and revocation not established",
    );
    expect(l.detail).toContain("minted a second ago");
    expect(l.detail).toContain("not trust");
  });

  it("anchored names the independent RPC and does not say 'confirmed on-chain'", () => {
    const l = resultLabels(ok({ binding: "anchored" }));
    expect(l.tone).toBe("bound");
    expect(l.grade).toBe("ANCHORED");
    expect(l.detail).toContain("RPC the operator does not run");
    expect(l.detail).not.toMatch(/confirmed on-chain/i);
  });

  it("revoked is the loudest verdict — failed tone, do-not-trust, even with valid integrity", () => {
    const l = resultLabels(ok({ binding: "revoked", revokedAt: 1500 }));
    expect(l.tone).toBe("failed");
    expect(l.headline.toLowerCase()).toContain("revoked");
    expect(l.headline.toLowerCase()).toContain("do not trust");
    expect(l.detail.toLowerCase()).toContain("revoked");
    expect(l.detail).not.toContain(PROXY_LABEL);
    const viaProxy = resultLabels(
      ok({ binding: "revoked", revokedAt: 1500, chainSource: "operator-proxy" }),
    );
    expect(viaProxy.grade).toBe("REVOKED");
    expect(viaProxy.detail).toContain(PROXY_LABEL);
  });

  it("failed signature reads as altered/forged, not a vague error", () => {
    const l = resultLabels({
      integrity: false,
      binding: "unverified",
      reason: "signature_invalid",
    });
    expect(l.tone).toBe("failed");
    expect(l.detail).toContain("altered or forged");
  });

  it("malformed input gets an actionable JSON message", () => {
    const l = resultLabels({ integrity: false, binding: "unverified", reason: "malformed_json" });
    expect(l.tone).toBe("failed");
    expect(l.detail).toContain("valid JSON");
  });

  it("missing reason falls back to a generic failure", () => {
    const l = resultLabels({ integrity: false, binding: "unverified" });
    expect(l.tone).toBe("failed");
    expect(l.detail).toBe("Verification failed.");
  });
});
