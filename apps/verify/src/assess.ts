/**
 * The display verdict — what the page is allowed to CLAIM, given the verifier's
 * view model AND what the page knows about the evidence behind it. Every render
 * path (labels, ladder, honesty, render) consumes `DisplayVerdict`, never the raw
 * `ReceiptDocumentVerification`, so a claim stronger than its evidence is not a
 * value the renderers can be handed.
 *
 * Three downgrades (receipt.computer cold review, F-1 / F-2):
 *
 *   1. The receipt-alone genesis commitment (`binding: "sovereign"` — the
 *      motebit_id is a hash of the signing key) is shown as `key-commitment`:
 *      integrity holds and the id commits to the motebit's ORIGINAL key, but no
 *      time-windowed succession check ran, so whether that key was rotated away
 *      or revoked when it signed is not established. Never SOVEREIGN.
 *   2. `anchored` stands only when the on-chain root was read through an RPC
 *      the operator does not run. Read via Motebit's RPC proxy, it is shown as
 *      `pinned` with the anchor labelled "via Motebit's RPC proxy (not
 *      independently confirmed)".
 *   3. Revocation is ✓ only when the scan came from an independent RPC AND is
 *      provably complete (fewer signatures returned than the page limit). A
 *      failed, truncated, or proxy-only scan is `not_established`.
 *
 * A found revocation (the poison verdict) is shown whatever the source — that
 * direction fails closed — but a proxy source is still labelled.
 */

import type { ReceiptDocumentVerification } from "@motebit/state-export-client";

/** Who answered the Solana JSON-RPC reads behind the anchor/revocation rungs. */
export type ChainSource = "operator-proxy" | "independent";

/** The exact provenance label for anything read through the operator's proxy. */
export const PROXY_LABEL = "via Motebit's RPC proxy (not independently confirmed)";

/**
 * Classify an RPC URL. Hosts the operator runs (motebit.com, receipt.computer
 * and their subdomains) are the operator proxy; an unparseable URL is treated
 * as the proxy too (fail-closed — it never earns the independent label).
 */
export function classifyRpc(url: string): ChainSource {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return "operator-proxy";
  }
  const operator = ["motebit.com", "receipt.computer"];
  return operator.some((d) => host === d || host.endsWith(`.${d}`))
    ? "operator-proxy"
    : "independent";
}

/** One `getSignaturesForAddress` call as the page observed it. */
export interface ScanObservation {
  /** The `limit` the request asked for (undefined when it could not be read). */
  readonly limit?: number;
  /** How many signatures came back (undefined on any failure). */
  readonly returned?: number;
  readonly ok: boolean;
}

/**
 * Wrap `fetch` so every `getSignaturesForAddress` response is recorded — the
 * verifier does not report whether its scan saw every signature, so the page
 * measures it. The wrapped fetch returns the original response untouched.
 */
export function observeSignatureScans(base: typeof globalThis.fetch): {
  readonly fetch: typeof globalThis.fetch;
  readonly scans: ScanObservation[];
} {
  const scans: ScanObservation[] = [];
  const wrapped: typeof globalThis.fetch = async (input, init) => {
    let limit: number | undefined;
    let isScan = false;
    try {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "null") as {
        method?: unknown;
        params?: unknown;
      } | null;
      if (body?.method === "getSignaturesForAddress") {
        isScan = true;
        const opts = Array.isArray(body.params) ? (body.params[1] as { limit?: unknown }) : null;
        if (typeof opts?.limit === "number") limit = opts.limit;
      }
    } catch {
      /* not a JSON-RPC body */
    }
    let res: Response;
    try {
      res = await base(input, init);
    } catch (err) {
      if (isScan) scans.push({ ok: false, ...(limit !== undefined ? { limit } : {}) });
      throw err;
    }
    if (isScan) {
      let returned: number | undefined;
      try {
        const parsed = (await res.clone().json()) as { result?: unknown; error?: unknown };
        if (parsed.error === undefined && Array.isArray(parsed.result))
          returned = parsed.result.length;
      } catch {
        /* unreadable — not complete */
      }
      scans.push({
        ok: res.ok && returned !== undefined,
        ...(limit !== undefined ? { limit } : {}),
        ...(returned !== undefined ? { returned } : {}),
      });
    }
    return res;
  };
  return { fetch: wrapped, scans };
}

/**
 * True iff there was at least one scan, every scan succeeded, and every scan
 * returned strictly fewer signatures than it asked for — i.e. it reached the
 * end of the address's history instead of stopping at the page limit.
 */
export function scansComplete(scans: readonly ScanObservation[]): boolean {
  return (
    scans.length > 0 &&
    scans.every(
      (s) => s.ok && s.limit !== undefined && s.returned !== undefined && s.returned < s.limit,
    )
  );
}

/** What the page knows about the chain evidence behind one verification. */
export interface ChainEvidence {
  readonly source: ChainSource;
  /** The revocation scan provably saw every signature at the relay address. */
  readonly revocationScanComplete: boolean;
}

/** The binding the page may show. There is no "sovereign" here by design. */
export type DisplayBinding =
  "revoked" | "key-commitment" | "anchored" | "pinned" | "integrity-only" | "unverified";

export type DisplayRevocation =
  "not_revoked" | "revoked_after_signing" | "revoked" | "not_established";

export interface DisplayVerdict {
  readonly integrity: boolean;
  readonly binding: DisplayBinding;
  readonly anchorTxHash?: string;
  readonly revokedAt?: number;
  /** Absent ⇒ revocation was not attempted (offline / nested). */
  readonly revocation?: DisplayRevocation;
  /** Why revocation is `not_established` (failure, truncation, proxy). */
  readonly revocationNote?: string;
  /** Who answered the chain reads, when any were made. */
  readonly chainSource?: ChainSource;
  /** The verifier reached `anchored`, but only through the operator proxy. */
  readonly anchorViaProxy?: boolean;
  readonly signerDid?: string;
  readonly motebitId?: string;
  readonly taskId?: string;
  readonly delegations?: DisplayVerdict[];
  readonly reason?: ReceiptDocumentVerification["reason"];
  readonly detail?: string;
}

function revocationNotEstablished(
  v: ReceiptDocumentVerification,
  evidence: ChainEvidence | undefined,
): string | null {
  if (v.revocation === "unknown") {
    return `the on-chain lookup failed${v.revocationDetail ? ` (${v.revocationDetail})` : ""}`;
  }
  if (v.revocation !== "not_revoked" && v.revocation !== "revoked_after_signing") return null;
  if (evidence === undefined) return "the source of the on-chain lookup is unknown";
  if (evidence.source === "operator-proxy") {
    return `the on-chain lookup was read ${PROXY_LABEL}`;
  }
  if (!evidence.revocationScanComplete) {
    return "the scan stopped at the 200-signature page limit, so an older revocation may not have been seen";
  }
  return null;
}

/** Map the verifier's view + the page's evidence to the claim the page may show. */
export function assessVerdict(
  v: ReceiptDocumentVerification,
  evidence?: ChainEvidence,
): DisplayVerdict {
  let binding: DisplayBinding;
  let anchorViaProxy = false;
  switch (v.binding) {
    case "sovereign":
      binding = "key-commitment";
      break;
    case "anchored":
      if (evidence?.source === "independent") {
        binding = "anchored";
      } else {
        binding = "pinned";
        anchorViaProxy = true;
      }
      break;
    default:
      binding = v.binding;
  }

  const out: { -readonly [K in keyof DisplayVerdict]: DisplayVerdict[K] } = {
    integrity: v.integrity,
    binding,
  };
  if (binding === "anchored" && v.anchorTxHash !== undefined) out.anchorTxHash = v.anchorTxHash;
  if (anchorViaProxy) out.anchorViaProxy = true;
  if (v.revokedAt !== undefined) out.revokedAt = v.revokedAt;
  if (v.revocation !== undefined) {
    const why = revocationNotEstablished(v, evidence);
    if (why !== null) {
      out.revocation = "not_established";
      out.revocationNote = why;
    } else {
      out.revocation = v.revocation === "unknown" ? "not_established" : v.revocation;
    }
  }
  if (evidence !== undefined && (v.revocation !== undefined || v.binding === "anchored")) {
    out.chainSource = evidence.source;
  }
  if (v.signerDid !== undefined) out.signerDid = v.signerDid;
  if (v.motebitId !== undefined) out.motebitId = v.motebitId;
  if (v.taskId !== undefined) out.taskId = v.taskId;
  if (v.reason !== undefined) out.reason = v.reason;
  if (v.detail !== undefined) out.detail = v.detail;
  if (v.delegations !== undefined) out.delegations = v.delegations.map((d) => assessVerdict(d));
  return out;
}
