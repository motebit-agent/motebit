/**
 * The PROOF ladder — one row per rung (integrity / identity binding / revocation),
 * each passed (✓), not established or not checked (—, always with the reason), or
 * failed (✗). Mapped from the DISPLAY verdict (`assess.ts`): the verifier's view
 * model (`@motebit/state-export-client`'s `ReceiptDocumentVerification`)
 * downgraded to what the page's evidence supports — no receipt-alone sovereign,
 * no anchored or revocation ✓ on proxy-only or truncated chain reads — plus the
 * one fact the page itself owns: whether it asked the relay for binding material.
 * No rung is ever implied — a rung the page did not establish says so and why.
 */

import { PROXY_LABEL, type DisplayVerdict } from "./assess.js";

export type RungState = "passed" | "skipped" | "failed";
export type RungKey = "integrity" | "binding" | "revocation";

export interface Rung {
  readonly key: RungKey;
  readonly name: string;
  readonly state: RungState;
  /** For the binding rung when passed: which level. */
  readonly level?: "pinned" | "anchored";
  readonly summary: string;
}

/**
 * What the page did about relay context (the `pinned` / `anchored` / revocation
 * material). `offline`: not attempted, with the reason (sample, minted, …).
 * `unavailable`: attempted, the relay returned nothing usable (fail-closed).
 * `resolved`: the material was fetched and passed to the verifier.
 * `nested`: a delegated receipt — the verifier checks nested receipts for
 * integrity only.
 */
export type RelayContext =
  | { readonly kind: "offline"; readonly reason: string }
  | { readonly kind: "unavailable"; readonly reason: string }
  | { readonly kind: "resolved" }
  | { readonly kind: "nested" };

const NESTED_REASON = "not checked: nested receipts are verified for integrity only";

function integrityRung(v: DisplayVerdict): Rung {
  return v.integrity
    ? {
        key: "integrity",
        name: "Integrity",
        state: "passed",
        summary: "the signature matches these exact bytes, under the key embedded in the receipt",
      }
    : {
        key: "integrity",
        name: "Integrity",
        state: "failed",
        summary: v.detail
          ? `the signature does not match — ${v.detail}`
          : "the signature does not match",
      };
}

function bindingRung(v: DisplayVerdict, ctx: RelayContext): Rung {
  const base = { key: "binding" as const, name: "Identity binding" };
  switch (v.binding) {
    case "key-commitment":
      return {
        ...base,
        state: "skipped",
        summary:
          "not established as current — identity commitment matches the motebit's original key; rotation and revocation not established (the motebit_id is a hash of this key, checked offline; no succession check ran)",
      };
    case "anchored":
      return {
        ...base,
        state: "passed",
        level: "anchored",
        summary: v.anchorTxHash
          ? `anchored — the key is in the relay's identity log, whose root was found on-chain through an independent RPC (tx ${v.anchorTxHash})`
          : "anchored — the key is in the relay's identity log, whose root was found on-chain through an independent RPC",
      };
    case "pinned":
      return {
        ...base,
        state: "passed",
        level: "pinned",
        summary: v.anchorViaProxy
          ? `pinned — the key is time-valid in this motebit's identity chain, as served by the relay; the relay's on-chain anchor was read ${PROXY_LABEL}`
          : "pinned — the key is time-valid in this motebit's identity chain, as served by the relay",
      };
    case "revoked":
      return {
        ...base,
        state: "failed",
        summary: "the signing key was revoked at or before this receipt, so it does not bind",
      };
    case "unverified":
      return { ...base, state: "skipped", summary: "not checked: integrity failed" };
    default: {
      // integrity-only: the offline commitment check ran and did not match; the
      // relay rungs depend on context.
      if (ctx.kind === "nested") return { ...base, state: "skipped", summary: NESTED_REASON };
      const why =
        ctx.kind === "offline"
          ? ctx.reason
          : ctx.kind === "unavailable"
            ? ctx.reason
            : "the relay's identity chain does not bind this key";
      return {
        ...base,
        state: "skipped",
        summary: `not established — the motebit_id is not a commitment to this key; pinned/anchored: ${why}`,
      };
    }
  }
}

function revocationRung(v: DisplayVerdict, ctx: RelayContext): Rung {
  const base = { key: "revocation" as const, name: "Revocation" };
  if (v.binding === "revoked" || v.revocation === "revoked") {
    const when =
      v.revokedAt !== undefined
        ? `revoked on-chain at ${new Date(v.revokedAt).toISOString()}, at or before this receipt`
        : "revoked on-chain at or before this receipt";
    return {
      ...base,
      state: "failed",
      summary: v.chainSource === "operator-proxy" ? `${when} — read ${PROXY_LABEL}` : when,
    };
  }
  if (!v.integrity) return { ...base, state: "skipped", summary: "not checked: integrity failed" };
  switch (v.revocation) {
    case "not_revoked":
      return {
        ...base,
        state: "passed",
        summary:
          "no on-chain revocation found for the signing key — a complete scan through an independent RPC",
      };
    case "revoked_after_signing":
      return {
        ...base,
        state: "passed",
        summary:
          v.revokedAt !== undefined
            ? `not revoked when signed — the key was revoked later, at ${new Date(v.revokedAt).toISOString()}`
            : "not revoked when signed — the key was revoked later",
      };
    case "not_established":
      return {
        ...base,
        state: "skipped",
        summary: `not established: ${v.revocationNote ?? "the on-chain lookup did not complete"}`,
      };
    default:
      if (ctx.kind === "nested") return { ...base, state: "skipped", summary: NESTED_REASON };
      if (ctx.kind === "resolved") return { ...base, state: "skipped", summary: "not checked" };
      return { ...base, state: "skipped", summary: `not checked: ${ctx.reason}` };
  }
}

export function proofLadder(v: DisplayVerdict, ctx: RelayContext): Rung[] {
  return [integrityRung(v), bindingRung(v, ctx), revocationRung(v, ctx)];
}
