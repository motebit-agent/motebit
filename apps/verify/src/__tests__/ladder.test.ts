import { describe, it, expect } from "vitest";
import { proofLadder, type RelayContext, type Rung } from "../ladder.js";
import { PROXY_LABEL, type DisplayVerdict } from "../assess.js";

const OFFLINE: RelayContext = { kind: "offline", reason: "offline — sample" };
const RESOLVED: RelayContext = { kind: "resolved" };
const v = (over: Partial<DisplayVerdict>): DisplayVerdict => ({
  integrity: true,
  binding: "integrity-only",
  ...over,
});
const rung = (rs: Rung[], key: Rung["key"]): Rung => rs.find((r) => r.key === key)!;

describe("proofLadder", () => {
  it("always returns the three rungs, in order", () => {
    expect(proofLadder(v({}), OFFLINE).map((r) => r.key)).toEqual([
      "integrity",
      "binding",
      "revocation",
    ]);
  });

  it("integrity: passed / failed (with the verifier's detail)", () => {
    expect(rung(proofLadder(v({}), OFFLINE), "integrity").state).toBe("passed");
    const failed = rung(
      proofLadder(v({ integrity: false, binding: "unverified", detail: "bad sig" }), OFFLINE),
      "integrity",
    );
    expect(failed.state).toBe("failed");
    expect(failed.summary).toContain("bad sig");
  });

  it("binding: pinned and anchored map to a passed level", () => {
    for (const level of ["pinned", "anchored"] as const) {
      const r = rung(proofLadder(v({ binding: level }), RESOLVED), "binding");
      expect(r.state).toBe("passed");
      expect(r.level).toBe(level);
      expect(r.summary.startsWith(level)).toBe(true);
    }
    const anchored = rung(
      proofLadder(v({ binding: "anchored", anchorTxHash: "TX" }), RESOLVED),
      "binding",
    );
    expect(anchored.summary).toContain("TX");
    expect(anchored.summary).toContain("independent RPC");
  });

  it("binding: a key commitment is never ✓ and says rotation and revocation are not established", () => {
    for (const ctx of [OFFLINE, RESOLVED]) {
      const r = rung(proofLadder(v({ binding: "key-commitment" }), ctx), "binding");
      expect(r.state).toBe("skipped");
      expect(r.level).toBeUndefined();
      expect(r.summary).toContain(
        "identity commitment matches the motebit's original key; rotation and revocation not established",
      );
      expect(r.summary).not.toMatch(/sovereign/i);
    }
  });

  it("binding: pinned with a proxy-read anchor carries the proxy label", () => {
    const r = rung(
      proofLadder(v({ binding: "pinned", anchorViaProxy: true }), RESOLVED),
      "binding",
    );
    expect(r.level).toBe("pinned");
    expect(r.summary).toContain(PROXY_LABEL);
  });

  it("binding: integrity-only is never failed and always says why (per context)", () => {
    const off = rung(proofLadder(v({}), OFFLINE), "binding");
    expect(off.state).toBe("skipped");
    expect(off.level).toBeUndefined();
    expect(off.summary).toContain("offline — sample");
    const un = rung(proofLadder(v({}), { kind: "unavailable", reason: "relay down" }), "binding");
    expect(un.summary).toContain("relay down");
    const res = rung(proofLadder(v({}), RESOLVED), "binding");
    expect(res.summary).toContain("does not bind this key");
    const nested = rung(proofLadder(v({}), { kind: "nested" }), "binding");
    expect(nested.summary).toContain("nested receipts");
  });

  it("binding: revoked → failed; integrity failure → not checked", () => {
    expect(rung(proofLadder(v({ binding: "revoked" }), RESOLVED), "binding").state).toBe("failed");
    const r = rung(proofLadder(v({ integrity: false, binding: "unverified" }), OFFLINE), "binding");
    expect(r.state).toBe("skipped");
    expect(r.summary).toBe("not checked: integrity failed");
  });

  it("revocation: every display state maps strictly", () => {
    const rev = (over: Partial<DisplayVerdict>, ctx: RelayContext = RESOLVED) =>
      rung(proofLadder(v(over), ctx), "revocation");
    expect(rev({ revocation: "not_revoked" }).state).toBe("passed");
    const later = rev({ revocation: "revoked_after_signing", revokedAt: 3000 });
    expect(later.state).toBe("passed");
    expect(later.summary).toContain("revoked later");
    const bad = rev({ binding: "revoked", revocation: "revoked", revokedAt: 1500 });
    expect(bad.state).toBe("failed");
    expect(bad.summary).toContain("1970-01-01T00:00:01.500Z");
    expect(bad.summary).not.toContain(PROXY_LABEL);
    const badProxy = rev({
      binding: "revoked",
      revocation: "revoked",
      revokedAt: 1500,
      chainSource: "operator-proxy",
    });
    expect(badProxy.state).toBe("failed");
    expect(badProxy.summary).toContain(PROXY_LABEL);
    const ne = rev({ revocation: "not_established", revocationNote: "rpc down" });
    expect(ne.state).toBe("skipped");
    expect(ne.summary).toBe("not established: rpc down");
    // Absent ⇒ not checked, never "passed".
    expect(rev({}, OFFLINE).state).toBe("skipped");
    expect(rev({}, OFFLINE).summary).toBe("not checked: offline — sample");
    expect(rev({}, { kind: "nested" }).summary).toContain("nested receipts");
    expect(rev({ integrity: false, binding: "unverified" }, OFFLINE).summary).toBe(
      "not checked: integrity failed",
    );
  });
});
