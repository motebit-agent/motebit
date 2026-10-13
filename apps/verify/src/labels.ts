/**
 * Display logic for a verified receipt — maps the display verdict (`assess.ts`:
 * the verifier's view, downgraded to what the page's evidence supports) to the
 * words and tone the page shows. Kept pure and separate from `render.ts` (DOM)
 * so the one thing that MUST stay honest — never claiming more than the
 * evidence — is unit-tested.
 */

import type { ReceiptDocumentFailureReason } from "@motebit/state-export-client";
import { PROXY_LABEL, sourceLabel, type DisplayVerdict } from "./assess.js";
import { chainReason } from "./served-chain.js";

/** Drives the result card's color treatment. */
export type ResultTone = "bound" | "integrity" | "failed";

export interface ResultLabels {
  readonly tone: ResultTone;
  /** Short, all-caps "grade" for the verdict badge (the rung reached). */
  readonly grade: string;
  readonly headline: string;
  readonly detail: string;
}

const FAILURE_DETAIL: Record<ReceiptDocumentFailureReason, string> = {
  malformed_json: "That isn't valid JSON. Paste the full receipt object.",
  not_a_receipt:
    "Valid JSON, but not an execution receipt (missing motebit_id / task_id / signature / suite).",
  missing_public_key: "No embedded public key — this receipt can't be verified offline.",
  signature_invalid: "The signature does not match the receipt body — it was altered or forged.",
  delegation_failed: "A delegated receipt in the chain failed verification.",
  unknown: "Verification failed.",
};

export function resultLabels(v: DisplayVerdict): ResultLabels {
  // A reported revocation is the loudest verdict, and it fails closed — but it
  // is REPORTED, not proven: the lookup matches the memo's text and never checks
  // who signed the transaction, so anyone can post one naming any key.
  if (v.binding === "revoked") {
    return {
      tone: "failed",
      grade: "REVOCATION REPORTED",
      headline: "REVOCATION REPORTED (unauthenticated) — do not rely on this receipt",
      detail: `The signature matches, but a memo naming this signing key as revoked, dated at or before this receipt, was found at the relay's anchor address, read ${sourceLabel(v.chainSource)}. The memo is unauthenticated — this page does not check who posted it, and anyone can — so it does not prove the key was revoked. Until the revocation is checked, do not rely on this receipt's identity claim, even though the bytes are intact.`,
    };
  }
  if (!v.integrity) {
    return {
      tone: "failed",
      grade: "INVALID",
      headline: "Verification failed",
      detail: FAILURE_DETAIL[v.reason ?? "unknown"] ?? FAILURE_DETAIL.unknown,
    };
  }
  if (v.binding === "key-commitment") {
    // The motebit_id is the self-certifying commitment to this very key (its
    // genesis key). Lower assurance than any bound rung: that arithmetic says
    // nothing about whether the key was still the motebit's when it signed.
    const succession =
      v.chainCheck !== undefined
        ? `A succession check ran against the identity chain the relay served and did not bind this key at the receipt's time: ${chainReason(v.chainCheck)}.`
        : "Rotation and revocation not established — no succession check ran, so this page did not check whether that key had been rotated away or revoked when it signed.";
    return {
      tone: "integrity",
      grade: "KEY COMMITMENT",
      headline: "Signature verified — current authorization not established",
      detail: `The signature is valid and the receipt is untampered. The motebit_id is the self-certifying commitment to this signing key: identity commitment matches the motebit's original key. ${succession} A key minted a second ago commits the same way; this is not trust.`,
    };
  }
  if (v.binding === "anchored") {
    return {
      tone: "bound",
      grade: "ANCHORED",
      headline: "Verified — anchored",
      detail:
        "The signature is valid, the signing key is time-valid in this motebit's identity chain, and that binding is committed in the operator's transparency log, whose root was found at the relay's pinned address through a Solana RPC the operator does not run.",
    };
  }
  if (v.binding === "pinned") {
    const root =
      v.chainRoot === "id-commitment"
        ? ", whose genesis key is the one this motebit_id commits to (checked offline)"
        : v.chainRoot === "relay-record"
          ? " (this motebit_id commits to no key, so the chain's root is the relay's record)"
          : "";
    const proxy = v.anchorViaProxy
      ? ` The relay also reports an on-chain anchor for this chain, read ${PROXY_LABEL}, so the anchored rung is not claimed.`
      : "";
    return {
      tone: "bound",
      grade: "PINNED",
      headline: "Verified — identity pinned",
      detail: `The signature is valid and the signing key was time-valid at this receipt's time in the identity chain the relay served${root}. That binds the key to this motebit's chain as served — a later rotation the relay did not serve would not show here, and the chain is not shown to be committed in the operator's transparency log (the anchored rung).${proxy}`,
    };
  }
  // integrity-only: the honest default. Signature is valid, but it was checked
  // against the receipt's OWN embedded key — that proves the bytes weren't
  // tampered, NOT that the key belongs to this motebit.
  const anchor =
    v.chainCheck !== undefined
      ? `The identity chain the relay served does not bind this key: ${chainReason(v.chainCheck)}.`
      : "No trust anchor was provided.";
  return {
    tone: "integrity",
    grade: "INTEGRITY ONLY",
    headline: "Signature verified — identity not anchored",
    detail: `The signature is valid and the receipt is untampered, but it was checked against the receipt's own embedded key. That proves integrity, not that the key belongs to this motebit. ${anchor}`,
  };
}
