/**
 * The page's own check of a relay-served identity chain (`served-chain.ts`):
 * time-windowed, with no guardian named inside the served file honoured, and a
 * self-certifying id required to root at the key it commits to.
 */
import { describe, it, expect } from "vitest";
import { verifyKeyBindingAtTime, type MotebitIdentityFile } from "@motebit/crypto";
import {
  checkServedChain,
  chainReason,
  idCommitsToKey,
  isSelfCertifyingId,
} from "../served-chain.js";
import G1 from "./fixtures/G1-genesis-current-chain-served.json?raw";
import G1_CTX from "./fixtures/G1-genesis-current-chain-served.ctx.json?raw";
import G2 from "./fixtures/G2-historical-before-rotation-chain-served.json?raw";
import G2_CTX from "./fixtures/G2-historical-before-rotation-chain-served.ctx.json?raw";
import G3 from "./fixtures/G3-rotated-key-chain-served.json?raw";
import G3_CTX from "./fixtures/G3-rotated-key-chain-served.ctx.json?raw";
import D4A from "./fixtures/D4a-retired-genesis-after-rotation.json?raw";
import D4A_CTX from "./fixtures/D4a-retired-genesis-after-rotation.ctx.json?raw";
import D5 from "./fixtures/D5-pinned.json?raw";
import D5_CTX from "./fixtures/D5-pinned.ctx.json?raw";
import FG from "./fixtures/FG-forged-guardian-recovery.json?raw";
import FG_CTX from "./fixtures/FG-forged-guardian-recovery.ctx.json?raw";
import FGL from "./fixtures/FGL-forged-guardian-recovery-legacy.json?raw";
import FGL_CTX from "./fixtures/FGL-forged-guardian-recovery-legacy.ctx.json?raw";
import FS from "./fixtures/FS-served-genesis-not-id-commitment.json?raw";
import FS_CTX from "./fixtures/FS-served-genesis-not-id-commitment.ctx.json?raw";

interface Bundle {
  motebit_id: string;
  created_at: string;
  current_public_key: string;
  guardian_public_key?: string;
  succession: MotebitIdentityFile["succession"];
}
interface Receipt {
  motebit_id: string;
  public_key: string;
  completed_at: number;
}

/** The same reconstruction relay-binding.ts does: binding-relevant fields only. */
function identityOf(ctx: string): MotebitIdentityFile {
  const b = (JSON.parse(ctx) as { bundle: Bundle }).bundle;
  return {
    spec: "motebit/identity@1.0",
    motebit_id: b.motebit_id,
    created_at: b.created_at,
    owner_id: "",
    identity: { algorithm: "Ed25519", public_key: b.current_public_key },
    ...(b.guardian_public_key
      ? { guardian: { public_key: b.guardian_public_key, established_at: b.created_at } }
      : {}),
    governance: {
      trust_mode: "guarded",
      max_risk_auto: "0",
      require_approval_above: "0",
      deny_above: "0",
      operator_mode: false,
    },
    privacy: { default_sensitivity: "none", retention_days: {}, fail_closed: true },
    memory: { half_life_days: 30, confidence_threshold: 0.5, per_turn_limit: 5 },
    devices: [],
    succession: b.succession,
  } as MotebitIdentityFile;
}
const r = (text: string): Receipt => JSON.parse(text) as Receipt;

describe("checkServedChain", () => {
  it("binds the key at the receipt's time: genesis, historical, rotated-to", async () => {
    for (const [rec, ctx] of [
      [G1, G1_CTX],
      [G2, G2_CTX],
      [G3, G3_CTX],
    ] as const) {
      expect(await checkServedChain(r(rec), identityOf(ctx))).toEqual({
        kind: "bound",
        root: "id-commitment",
      });
    }
  });

  it("a legacy id binds with the relay's record as the root", async () => {
    expect(await checkServedChain(r(D5), identityOf(D5_CTX))).toEqual({
      kind: "bound",
      root: "relay-record",
    });
  });

  it("a retired key signing after its rotation is not active", async () => {
    expect(await checkServedChain(r(D4A), identityOf(D4A_CTX))).toEqual({ kind: "not_active" });
  });

  it("a guardian named only inside the served file never binds — though the library alone would", async () => {
    for (const [rec, ctx] of [
      [FG, FG_CTX],
      [FGL, FGL_CTX],
    ] as const) {
      const id = identityOf(ctx);
      // The hazard this module exists for: the library honours the file's guardian.
      const lib = await verifyKeyBindingAtTime(id, r(rec).public_key, r(rec).completed_at);
      expect(lib.bound).toBe(true);
      expect(await checkServedChain(r(rec), id)).toEqual({ kind: "recovery_unverifiable" });
    }
  });

  it("a self-certifying id whose served chain roots elsewhere does not bind", async () => {
    expect(await checkServedChain(r(FS), identityOf(FS_CTX))).toEqual({ kind: "root_mismatch" });
  });

  it("another motebit's record, a key outside the chain, and unusable input fail closed", async () => {
    const other = { ...r(D5), motebit_id: "019dc500-0000-7abc-8000-0000000000aa" };
    expect(await checkServedChain(other, identityOf(D5_CTX))).toEqual({ kind: "other_motebit" });
    expect(await checkServedChain(r(FS), identityOf(G1_CTX))).toEqual({ kind: "not_in_chain" });
    const bad = await checkServedChain({ motebit_id: "x" }, identityOf(D5_CTX));
    expect(bad.kind).toBe("invalid");
  });

  it("self-certifying ids and key commitments", async () => {
    expect(isSelfCertifyingId(r(G1).motebit_id)).toBe(true);
    expect(isSelfCertifyingId("did:key:z6Mk")).toBe(true);
    expect(isSelfCertifyingId(r(D5).motebit_id)).toBe(false);
    expect(await idCommitsToKey(r(G1).motebit_id, r(G1).public_key)).toBe(true);
    expect(await idCommitsToKey(r(G3).motebit_id, r(G3).public_key)).toBe(false);
    expect(await idCommitsToKey(undefined, r(G1).public_key)).toBe(false);
  });

  it("every non-binding outcome has a reason clause", () => {
    for (const k of [
      "not_active",
      "not_in_chain",
      "recovery_unverifiable",
      "root_mismatch",
      "other_motebit",
      "invalid",
    ] as const) {
      expect(chainReason(k).length).toBeGreaterThan(10);
    }
  });
});
