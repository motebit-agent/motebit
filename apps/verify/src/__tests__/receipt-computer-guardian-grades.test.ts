/**
 * receipt.computer grades for guardian-recovered identities — the consumer-level
 * pin for "a guardian named only by the artifact being verified can never
 * establish authority".
 *
 * receipt.computer builds its identity file from the relay's
 * `GET /api/v1/identity/:id` bundle, including `guardian_public_key`. That
 * guardian is at most as trusted as the relay, while the `sovereign` rung the
 * page shows means "offline, no operator". So the page passes NO trusted
 * guardian: a chain that runs through a guardian-recovery link no longer lifts
 * a receipt above `integrity-only`. This file mirrors `main.ts`'s exact call
 * (`verifyReceiptDocument(text, { identity: resolved.identity, ... })`) and
 * lists every grade, changed or not.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKeypair,
  bytesToHex,
  canonicalJson,
  sha256,
  signBySuite,
  signExecutionReceipt,
  deriveSovereignMotebitId,
  type KeyPair,
  type SuccessionRecord,
} from "@motebit/crypto";
import { verifyReceiptDocument } from "@motebit/state-export-client";
import { resolveReceiptBinding, type IdentityBundle } from "../relay-binding.js";

const SUITE = "motebit-jcs-ed25519-hex-v1" as const;
const RELAY = "https://relay.example.com";
const T0 = Date.parse("2026-01-01T00:00:00Z");
const T1 = Date.parse("2026-02-01T00:00:00Z");
const DAY = 24 * 60 * 60 * 1000;

let relay: KeyPair;

beforeAll(async () => {
  relay = await generateKeypair();
});

async function declaration(): Promise<unknown> {
  const payload = {
    spec: "motebit-transparency/draft-2026-04-14",
    declared_at: 1736500000000,
    relay_id: "relay-r",
    relay_public_key: bytesToHex(relay.publicKey),
    content: { purpose: "test", retention: "none" },
  };
  const canonical = new TextEncoder().encode(canonicalJson(payload));
  return {
    ...payload,
    hash: bytesToHex(await sha256(canonical)),
    suite: SUITE,
    signature: bytesToHex(await signBySuite(SUITE, canonical, relay.privateKey)),
  };
}

async function relayServing(b: IdentityBundle): Promise<typeof globalThis.fetch> {
  const decl = await declaration();
  return (async (url: string) => {
    if (url.includes("/.well-known/motebit-transparency.json"))
      return new Response(JSON.stringify(decl), { status: 200 });
    if (url.includes("/api/v1/identity/")) return new Response(JSON.stringify(b), { status: 200 });
    return new Response("?", { status: 500 });
  }) as unknown as typeof globalThis.fetch;
}

async function ordinaryLink(oldKp: KeyPair, newKp: KeyPair, timestamp: number) {
  const old_public_key = bytesToHex(oldKp.publicKey);
  const new_public_key = bytesToHex(newKp.publicKey);
  const msg = new TextEncoder().encode(
    canonicalJson({ old_public_key, new_public_key, timestamp, suite: SUITE }),
  );
  return {
    old_public_key,
    new_public_key,
    timestamp,
    suite: SUITE,
    old_key_signature: bytesToHex(await signBySuite(SUITE, msg, oldKp.privateKey)),
    new_key_signature: bytesToHex(await signBySuite(SUITE, msg, newKp.privateKey)),
  } as SuccessionRecord;
}

async function recoveryLink(oldPub: Uint8Array, newKp: KeyPair, g: KeyPair, timestamp: number) {
  const old_public_key = bytesToHex(oldPub);
  const new_public_key = bytesToHex(newKp.publicKey);
  const reason = "guardian_recovery";
  const msg = new TextEncoder().encode(
    canonicalJson({
      old_public_key,
      new_public_key,
      timestamp,
      suite: SUITE,
      reason,
      recovery: true,
    }),
  );
  return {
    old_public_key,
    new_public_key,
    timestamp,
    suite: SUITE,
    reason,
    recovery: true,
    new_key_signature: bytesToHex(await signBySuite(SUITE, msg, newKp.privateKey)),
    guardian_signature: bytesToHex(await signBySuite(SUITE, msg, g.privateKey)),
  } as SuccessionRecord;
}

async function receiptText(kp: KeyPair, motebitId: string, completedAt: number): Promise<string> {
  const unsigned = {
    task_id: `t-${completedAt}`,
    motebit_id: motebitId,
    device_id: "d",
    submitted_at: completedAt - 10,
    completed_at: completedAt,
    status: "completed",
    result: "ok",
    tools_used: [],
    memories_formed: 0,
    prompt_hash: "0".repeat(64),
    result_hash: "1".repeat(64),
    public_key: bytesToHex(kp.publicKey),
  } as unknown as Parameters<typeof signExecutionReceipt>[0];
  return JSON.stringify(await signExecutionReceipt(unsigned, kp.privateKey));
}

/** What main.ts does for a pasted receipt once the relay resolves (revocation omitted: no RPC). */
async function pageGrade(text: string, b: IdentityBundle): Promise<string> {
  const resolved = await resolveReceiptBinding({
    relayBase: RELAY,
    motebitId: b.motebit_id,
    fetch: await relayServing(b),
  });
  expect(resolved).not.toBeNull();
  const view = await verifyReceiptDocument(text, {
    identity: resolved!.identity,
    ...(resolved!.anchor ? { anchor: resolved!.anchor } : {}),
  });
  return view.binding;
}

function bundleFor(
  motebitId: string,
  current: KeyPair,
  succession: SuccessionRecord[],
  guardian?: KeyPair,
): IdentityBundle {
  return {
    motebit_id: motebitId,
    created_at: new Date(T0).toISOString(),
    current_public_key: bytesToHex(current.publicKey),
    ...(guardian ? { guardian_public_key: bytesToHex(guardian.publicKey) } : {}),
    succession,
    anchored: null,
  };
}

describe("receipt.computer grades — guardian recovery", () => {
  it("UNCHANGED: ordinary rotation, rotated-key receipt → sovereign", async () => {
    const genesis = await generateKeypair();
    const rotated = await generateKeypair();
    const id = await deriveSovereignMotebitId(bytesToHex(genesis.publicKey));
    const b = bundleFor(id, rotated, [await ordinaryLink(genesis, rotated, T1)]);
    expect(await pageGrade(await receiptText(rotated, id, T1 + DAY), b)).toBe("sovereign");
  });

  it("UNCHANGED: ordinary rotation with a relay-served guardian → sovereign (guardian not consulted)", async () => {
    const genesis = await generateKeypair();
    const rotated = await generateKeypair();
    const guardian = await generateKeypair();
    const id = await deriveSovereignMotebitId(bytesToHex(genesis.publicKey));
    const b = bundleFor(id, rotated, [await ordinaryLink(genesis, rotated, T1)], guardian);
    expect(await pageGrade(await receiptText(rotated, id, T1 + DAY), b)).toBe("sovereign");
  });

  it("UNCHANGED: genesis-key receipt of a recovered identity → sovereign (receipt-alone)", async () => {
    const genesis = await generateKeypair();
    const recovered = await generateKeypair();
    const guardian = await generateKeypair();
    const id = await deriveSovereignMotebitId(bytesToHex(genesis.publicKey));
    const b = bundleFor(
      id,
      recovered,
      [await recoveryLink(genesis.publicKey, recovered, guardian, T1)],
      guardian,
    );
    expect(await pageGrade(await receiptText(genesis, id, T0 + DAY), b)).toBe("sovereign");
  });

  it("CHANGED sovereign → integrity-only: a legitimate recovery whose guardian only the relay vouches for", async () => {
    const genesis = await generateKeypair();
    const recovered = await generateKeypair();
    const guardian = await generateKeypair();
    const id = await deriveSovereignMotebitId(bytesToHex(genesis.publicKey));
    const b = bundleFor(
      id,
      recovered,
      [await recoveryLink(genesis.publicKey, recovered, guardian, T1)],
      guardian,
    );
    expect(await pageGrade(await receiptText(recovered, id, T1 + DAY), b)).toBe("integrity-only");
  });

  it("CHANGED sovereign → integrity-only: a relay (or anyone) serving a forged guardian + recovery for a victim id", async () => {
    const victimPub = (await generateKeypair()).publicKey; // no victim secret
    const kAtt = await generateKeypair();
    const gAtt = await generateKeypair();
    const id = await deriveSovereignMotebitId(bytesToHex(victimPub));
    const b = bundleFor(id, kAtt, [await recoveryLink(victimPub, kAtt, gAtt, T1)], gAtt);
    expect(await pageGrade(await receiptText(kAtt, id, T1 + DAY), b)).toBe("integrity-only");
  });

  it("CHANGED pinned → integrity-only: a legacy (random) id whose chain runs through a recovery", async () => {
    const genesis = await generateKeypair();
    const recovered = await generateKeypair();
    const guardian = await generateKeypair();
    const b = bundleFor(
      "mote-legacy",
      recovered,
      [await recoveryLink(genesis.publicKey, recovered, guardian, T1)],
      guardian,
    );
    expect(await pageGrade(await receiptText(recovered, "mote-legacy", T1 + DAY), b)).toBe(
      "integrity-only",
    );
  });
});
