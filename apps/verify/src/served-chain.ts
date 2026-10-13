/**
 * The page's OWN check of the identity chain the relay served — the evidence
 * behind the PINNED rung and behind every sentence about how the signing key
 * relates to the motebit_id. `assess.ts` reads this, never the verifier's
 * `binding: "sovereign"`, because that one value covers two different checks
 * (the receipt-alone commitment and the time-windowed succession path) and the
 * second trusts a guardian key named inside the very file it is verifying.
 *
 * Two rules, both fail-closed:
 *
 *   1. A guardian-recovery link never binds here. The guardian key's only
 *      source is the relay-served bundle — the same source as the chain it
 *      would authorize — so a relay (or anyone answering for it) could name a
 *      guardian of its own and "recover" any motebit to any key. The page has
 *      no guardian key with independent provenance, so it hands the verifier
 *      none: the identity is passed WITHOUT its `guardian`, and a recovery link
 *      fails the chain. A legitimately recovered motebit therefore reads below
 *      PINNED on this page — an under-claim, stated as such in the copy.
 *   2. For a self-certifying id (a UUIDv8 commitment or a `did:key`), the
 *      served chain must root at the key the id commits to. A chain rooted
 *      anywhere else is the relay's word against the id's own arithmetic.
 *      A legacy (UUIDv7/v4) id commits to no key, so its chain is the relay's
 *      record by construction — PINNED says "as served by the relay".
 *
 * The time window is only as complete as the chain served: a later rotation
 * the relay withheld cannot be seen, which the PINNED copy says.
 */

import {
  verifyKeyBindingAtTime,
  verifySovereignBinding,
  type MotebitIdentityFile,
} from "@motebit/crypto";

/** The outcome of checking a relay-served chain against one receipt. */
export type ServedChainCheck =
  /** The key is time-valid at the receipt's time in a chain verified without any guardian link. */
  | { readonly kind: "bound"; readonly root: "id-commitment" | "relay-record" }
  /** The chain is valid and names the key, but not as active at the receipt's time. */
  | { readonly kind: "not_active" }
  /** The chain is valid and does not contain the key. */
  | { readonly kind: "not_in_chain" }
  /** The chain contains a guardian-recovery link, which this page cannot verify. */
  | { readonly kind: "recovery_unverifiable" }
  /** A self-certifying id, but the served chain roots at a different key. */
  | { readonly kind: "root_mismatch" }
  /** The served record is for another motebit_id. */
  | { readonly kind: "other_motebit" }
  /** The chain did not verify, or the receipt cannot be placed in time. */
  | { readonly kind: "invalid"; readonly reason: string };

const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** An id that commits to a key by itself: a sovereign UUIDv8 or a `did:key`. */
export function isSelfCertifyingId(motebitId: string): boolean {
  return UUID_V8.test(motebitId) || motebitId.startsWith("did:key:");
}

/** True iff `motebitId` is the self-certifying commitment to `publicKeyHex` (never throws). */
export async function idCommitsToKey(motebitId: unknown, publicKeyHex: unknown): Promise<boolean> {
  if (typeof motebitId !== "string" || typeof publicKeyHex !== "string") return false;
  return verifySovereignBinding(motebitId, publicKeyHex);
}

/** Check `receipt`'s signing key against the relay-served `identity`. Never throws. */
export async function checkServedChain(
  receipt: {
    readonly motebit_id?: unknown;
    readonly public_key?: unknown;
    readonly completed_at?: unknown;
  },
  identity: MotebitIdentityFile,
): Promise<ServedChainCheck> {
  const { motebit_id: id, public_key: key, completed_at: at } = receipt;
  if (typeof id !== "string" || typeof key !== "string" || typeof at !== "number") {
    return { kind: "invalid", reason: "the receipt has no signing key or completion time" };
  }
  if (String(identity.motebit_id) !== id) return { kind: "other_motebit" };
  // Rule 1: no guardian key reaches the verifier — see the module comment.
  const { guardian: _fileNamedGuardian, ...withoutGuardian } = identity;
  try {
    const r = await verifyKeyBindingAtTime(withoutGuardian, key, at);
    if (r.bound) {
      if (isSelfCertifyingId(id)) {
        // Rule 2: the chain must root at the key the id commits to.
        return r.sovereign === true
          ? { kind: "bound", root: "id-commitment" }
          : { kind: "root_mismatch" };
      }
      return { kind: "bound", root: "relay-record" };
    }
    if ((identity.succession ?? []).some((s) => s.recovery === true)) {
      return { kind: "recovery_unverifiable" };
    }
    if (r.reason?.includes("not active") === true) return { kind: "not_active" };
    if (r.reason?.includes("not in this identity") === true) return { kind: "not_in_chain" };
    return { kind: "invalid", reason: r.reason ?? "the succession chain did not verify" };
  } catch (err) {
    return { kind: "invalid", reason: err instanceof Error ? err.message : String(err) };
  }
}

/** Why a served chain did not bind the key — one clause, for the copy. */
export function chainReason(kind: Exclude<ServedChainCheck["kind"], "bound">): string {
  switch (kind) {
    case "not_active":
      return "the key is in the chain but not active at the receipt's time (a signed rotation had moved it away, or it was not yet in use)";
    case "not_in_chain":
      return "the chain does not contain this key";
    case "recovery_unverifiable":
      return "the chain contains a guardian-recovery link, and the only source of its guardian key is the relay's own record, so this page does not honour it";
    case "root_mismatch":
      return "the chain does not root at the key this motebit_id commits to";
    case "other_motebit":
      return "the relay's record is for a different motebit_id";
    case "invalid":
      return "the chain did not verify";
  }
}
