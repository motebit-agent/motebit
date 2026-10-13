/**
 * Display logic for a verified receipt — maps the display verdict (`assess.ts`:
 * the verifier's view, downgraded to what the page's evidence supports) to the
 * words and tone the page shows. Kept pure and separate from `render.ts` (DOM)
 * so the one thing that MUST stay honest — never claiming more than the
 * evidence — is unit-tested.
 */

import type { ReceiptDocumentFailureReason } from "@motebit/state-export-client";
import { PROXY_LABEL, type DisplayVerdict } from "./assess.js";

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
  // Revoked is the loudest verdict — the signature may be valid, but the signing
  // key was revoked on-chain at/before this receipt. Check it before everything.
  if (v.binding === "revoked") {
    const via =
      v.chainSource === "operator-proxy" ? ` The revocation was read ${PROXY_LABEL}.` : "";
    return {
      tone: "failed",
      grade: "REVOKED",
      headline: "Key revoked — do not trust",
      detail: `The signature matches, but the signing key was revoked on-chain at or before this receipt's time. A revoked key signals compromise or retirement — do not trust this receipt's identity claim, even though the bytes are intact.${via}`,
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
    // The receipt-alone genesis commitment. Lower assurance than any bound rung:
    // no time-windowed succession check ran, so the page does not claim the key
    // was still the motebit's when it signed.
    return {
      tone: "integrity",
      grade: "KEY COMMITMENT",
      headline: "Signature verified — current authorization not established",
      detail:
        "The signature is valid and the receipt is untampered. The motebit_id is a hash commitment to the signing key: identity commitment matches the motebit's original key; rotation and revocation not established — this page did not check whether that key had been rotated away or revoked when it signed. A key minted a second ago commits the same way; this is not trust.",
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
    const proxy = v.anchorViaProxy
      ? ` The relay also reports an on-chain anchor for this chain, read ${PROXY_LABEL}, so the anchored rung is not claimed.`
      : "";
    return {
      tone: "bound",
      grade: "PINNED",
      headline: "Verified — identity pinned",
      detail: `The signature is valid and the signing key is time-valid in the identity chain checked against — as served by the relay or supplied by you. That binds the key to this motebit's chain — it does not yet prove the chain is the operator's current, non-equivocable record (the anchored rung).${proxy}`,
    };
  }
  // integrity-only: the honest default. Signature is valid, but it was checked
  // against the receipt's OWN embedded key — that proves the bytes weren't
  // tampered, NOT that the key belongs to this motebit.
  return {
    tone: "integrity",
    grade: "INTEGRITY ONLY",
    headline: "Signature verified — identity not anchored",
    detail:
      "The signature is valid and the receipt is untampered, but it was checked against the receipt's own embedded key. That proves integrity, not that the key belongs to this motebit. No trust anchor was provided.",
  };
}
