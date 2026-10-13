/**
 * Tamper check for the receipt.computer overclaim mitigation (cold review F-1,
 * F-2, F-3; round 2: B served-chain binding, D truthful copy, G unauthenticated
 * revocation; round 3: F1 any memo is reported, F2 canonical ids only, F3 the
 * claimed time is a claim). Each entry reverts ONE fix point and names the tests that must go
 * red. The script applies the tamper, runs those tests, demands a non-zero exit,
 * and restores the file. An entry whose `find` text is not present exactly once
 * is a hard error — a tamper that silently fails to apply would be a false green.
 *
 *   node apps/verify/scripts/tamper-overclaim.mjs
 *   TAMPER_ONLY="F2:" node apps/verify/scripts/tamper-overclaim.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const APP = join(dirname(fileURLToPath(import.meta.url)), "..");

const TAMPERS = [
  {
    name: "F-3: typing no longer clears the previous verdict at once",
    file: "src/main.ts",
    find: "  runSeq++; // and any in-flight run for the previous text may no longer render\n  clearResult();\n",
    replace: "",
    tests: ["src/__tests__/page.test.ts", "-t", "typing"],
  },
  {
    name: "F-3: a verifier exception is no longer rendered as Not verified",
    file: "src/main.ts",
    find: "    if (seq === runSeq) resultContainer.replaceChildren(renderUnverifiable(err));",
    replace: "    throw err;",
    tests: ["src/__tests__/page.test.ts", "-t", "F-3"],
  },
  {
    name: "F-3: a run (share-link hashchange) no longer clears before verifying",
    file: "src/main.ts",
    find: "  clearResult();\n  verifyBtn.disabled = true;",
    replace: "  verifyBtn.disabled = true;",
    tests: ["src/__tests__/page.test.ts", "-t", "hashchange"],
  },
  {
    name: "F-1: the verifier's sovereign passes through to the page",
    file: "src/assess.ts",
    find: '  if (v.binding === "unverified") {\n    shown = "unverified";',
    replace:
      '  if (v.binding === "unverified" || v.binding === "sovereign") {\n    shown = v.binding as never;',
    tests: ["src/__tests__/page.test.ts", "-t", "SOVEREIGN"],
  },
  {
    name: "B: a served chain that binds the key no longer lifts the page to PINNED",
    file: "src/assess.ts",
    find: '  } else if (chain?.kind === "bound" && verifierBound) {',
    replace: "  } else if (false) {",
    tests: ["src/__tests__/page.test.ts", "-t", "PINNED, not KEY COMMITMENT"],
  },
  {
    name: "B: the page stops checking the served chain itself",
    file: "src/main.ts",
    find: "        servedChain: await checkServedChain(receipt, resolved.identity),\n",
    replace: "",
    tests: ["src/__tests__/page.test.ts", "-t", "PINNED, not KEY COMMITMENT"],
  },
  {
    name: "B: the page check hands the file-named guardian to the verifier",
    file: "src/served-chain.ts",
    find: "verifyKeyBindingAtTime(withoutGuardian, key, at)",
    replace: "verifyKeyBindingAtTime(identity, key, at)",
    tests: ["src/__tests__/page.test.ts", "-t", "guardian named only"],
  },
  {
    name: "B: a self-certifying id no longer has to root the served chain at its own key",
    file: "src/served-chain.ts",
    find: "        return r.sovereign === true\n",
    replace: "        return true\n",
    tests: ["src/__tests__/page.test.ts", "-t", "genesis is not the key"],
  },
  {
    name: "B: the verifier's pinned/anchored passes through without the page's chain check",
    file: "src/assess.ts",
    find: '  } else if (chain?.kind === "bound" && verifierBound) {',
    replace:
      '  } else if ((chain?.kind === "bound" || v.binding === "pinned" || v.binding === "anchored") && verifierBound) {',
    tests: ["src/__tests__/page.test.ts", "-t", "same forged guardian on a legacy id"],
  },
  {
    name: "B/D: KEY COMMITMENT shown without the id committing to the signing key",
    file: "src/assess.ts",
    find: '  } else if (keyEvidence.keyCommitsToId && v.binding === "sovereign") {',
    replace: '  } else if (v.binding === "sovereign") {',
    tests: ["src/__tests__/page.test.ts", "-t", "guardian named only"],
  },
  {
    name: "D: the served-chain outcome is dropped, so the copy says no succession check ran",
    file: "src/assess.ts",
    find: '  if (chain !== undefined && chain.kind !== "bound" && v.integrity) out.chainCheck = chain.kind;\n',
    replace: "",
    tests: [
      "src/__tests__/page.test.ts",
      "-t",
      "retired genesis key signing after rotation → KEY COMMITMENT",
    ],
  },
  {
    name: "D: the binding rung claims 'no succession check ran' after one ran",
    file: "src/ladder.ts",
    find: "          v.chainCheck !== undefined\n            ? `not bound",
    replace: "          false\n            ? `not bound",
    tests: [
      "src/__tests__/page.test.ts",
      "-t",
      "retired genesis key signing after rotation → KEY COMMITMENT",
    ],
  },
  {
    name: "D: the PINNED copy calls the served chain non-equivocable",
    file: "src/labels.ts",
    find: "The chain is not shown to be committed in the operator's transparency log (the anchored rung).",
    replace:
      "It does not yet prove the chain is the operator's current, non-equivocable record (the anchored rung).",
    tests: ["src/__tests__/page.test.ts", "-t", "PINNED, not KEY COMMITMENT"],
  },
  {
    name: "G: an unauthenticated revocation memo is graded REVOKED",
    file: "src/labels.ts",
    find: '      grade: "REVOCATION REPORTED",',
    replace: '      grade: "REVOKED",',
    tests: ["src/__tests__/page.test.ts", "-t", "third-party memo"],
  },
  {
    name: "G: the verdict headline says 'Key revoked'",
    file: "src/labels.ts",
    find: '      headline: "REVOCATION REPORTED (unauthenticated) — do not rely on this receipt",',
    replace: '      headline: "Key revoked — do not trust",',
    tests: ["src/__tests__/page.test.ts", "-t", "third-party memo"],
  },
  {
    name: "G: the revocation rung states 'revoked on-chain at' as fact",
    file: "src/ladder.ts",
    find: "      summary: `REVOCATION REPORTED (unauthenticated) — ${when}, reported whatever this receipt's claimed time; who posted it was not checked — read ${sourceLabel(v.chainSource)}`,",
    replace: "      summary: `revoked on-chain at ${when}`,",
    tests: ["src/__tests__/page.test.ts", "-t", "third-party memo"],
  },
  {
    name: "G: the claim chip says REVOKED",
    file: "src/render.ts",
    find: '      ? "REVOCATION REPORTED"\n      : "valid signature";',
    replace: '      ? "REVOKED"\n      : "valid signature";',
    tests: ["src/__tests__/page.test.ts", "-t", "third-party memo"],
  },
  {
    name: "F-1: a truncated revocation scan is no longer refused",
    file: "src/assess.ts",
    find: "  if (!evidence.revocationScanComplete) {",
    replace: "  if (false) {",
    tests: ["src/__tests__/page.test.ts", "-t", "truncated"],
  },
  {
    name: "F-1: the page stops measuring scan completeness (always 'complete')",
    file: "src/main.ts",
    find: "revocationScanComplete: scansComplete(revocationScan.scans),",
    replace: "revocationScanComplete: true,",
    tests: ["src/__tests__/page.test.ts", "-t", "truncated"],
  },
  {
    name: "F-1: a scan that returned exactly the page limit counts as complete",
    file: "src/assess.ts",
    find: "s.returned < s.limit",
    replace: "s.returned <= s.limit",
    tests: ["src/__tests__/page.test.ts", "-t", "page limit hit"],
  },
  {
    name: "F-2: a proxy-read revocation scan is no longer refused",
    file: "src/assess.ts",
    find: '  if (evidence.source === "operator-proxy") {',
    replace: "  if (false) {",
    tests: ["src/__tests__/page.test.ts", "-t", "proxy reporting no revocation"],
  },
  {
    name: "F-2: a proxy-read anchor renders ANCHORED",
    file: "src/assess.ts",
    find: '    if (v.binding === "anchored" && evidence?.source === "independent") {',
    replace: '    if (v.binding === "anchored") {',
    tests: ["src/__tests__/page.test.ts", "-t", "operator proxy: an anchor"],
  },
  {
    name: "F-2: the page treats its own RPC proxy as independent",
    file: "src/main.ts",
    find: "const SOLANA_RPC_SOURCE = classifyRpc(SOLANA_RPC);",
    replace: 'const SOLANA_RPC_SOURCE = "independent" as const;',
    tests: ["src/__tests__/page.test.ts", "-t", "F-2"],
  },
  {
    name: "F-2: the copy claims the browser queries Solana with the receipt's key",
    file: "index.html",
    find: "and read Solana\n              through Motebit's RPC proxy (api.motebit.com) at the relay's anchor address.",
    replace: "and Solana, with its public key.",
    tests: ["src/__tests__/page.test.ts", "-t", "page copy"],
  },
  // ── Round 3 ──
  {
    name: "F1: a memo dated after the claimed completed_at clears the key again",
    file: "src/assess.ts",
    find: '    v.revocation === "revoked_after_signing" ||\n',
    replace: "",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "memo dated after the claimed time"],
  },
  {
    name: "F1: the reported memo's date is again said to be at or before this receipt",
    file: "src/ladder.ts",
    find: ", reported whatever this receipt's claimed time;",
    replace: ", at or before this receipt;",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "memo dated before the claimed time"],
  },
  {
    name: "F1: the REPORTED card stops saying the claimed time cannot clear a memo",
    file: "src/labels.ts",
    find: "Its date is not weighed against this receipt's: ${CLAIMED_TIME}, and a receipt dated before the memo may have been signed after it. ",
    replace: "",
    tests: [
      "src/__tests__/claimed-vs-proven.test.ts",
      "-t",
      "memo dated exactly at the claimed time",
    ],
  },
  {
    name: "F1 nit: the binding rung is ✗ where the text says not established",
    file: "src/ladder.ts",
    find: '        state: "skipped",\n        summary: "not established — a revocation memo (unauthenticated) was reported for this key",',
    replace:
      '        state: "failed",\n        summary: "not established — a revocation memo (unauthenticated) was reported for this key",',
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "fabricated junk memo"],
  },
  {
    name: "F2: a non-canonical id is no longer refused by the served-chain check",
    file: "src/served-chain.ts",
    find: '  if (form === "noncanonical") return { kind: "noncanonical_id" };\n',
    replace: "",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "its own chain served → no binding"],
  },
  {
    name: "F2: any non-v8, non-did:key id falls back to the relay-record root",
    file: "src/served-chain.ts",
    find: "const UUID_LEGACY = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;",
    replace: "const UUID_LEGACY = /^[\\s\\S]*$/;",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "zero-width space"],
  },
  {
    name: "F2: the UUIDv8 match is case-insensitive again",
    file: "src/served-chain.ts",
    find: "const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;",
    replace:
      "const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;",
    tests: [
      "src/__tests__/claimed-vs-proven.test.ts",
      "-t",
      "uppercase UUIDv8 signed by the key it commits to",
    ],
  },
  {
    name: "F2: the did:key match accepts any case and any characters",
    file: "src/served-chain.ts",
    find: "const DID_KEY = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/;",
    replace: "const DID_KEY = /^did:key:/i;",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "DID:KEY uppercase prefix"],
  },
  {
    name: "F2: a key commitment is computed for a non-canonical id",
    file: "src/served-chain.ts",
    find: "  if (!isSelfCertifyingId(motebitId)) return false;\n",
    replace: "",
    tests: [
      "src/__tests__/claimed-vs-proven.test.ts",
      "-t",
      "uppercase UUIDv8 signed by the key it commits to",
    ],
  },
  {
    name: "F2: the page stops classifying the id, so the copy never says it is non-canonical",
    file: "src/main.ts",
    find: "        idForm: classifyId(receipt.motebit_id),\n",
    replace: "",
    // With the relay reachable the served-chain outcome still names the reason;
    // with it down, only the page's own classification can.
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "no key commitment"],
  },
  {
    name: "F3: the PINNED card drops what it does not prove",
    file: "src/labels.ts",
    find: " This does not prove when the receipt was issued, that the relay served the complete history (a later rotation the relay did not serve would not show here), or that the key was uncompromised.",
    replace: " A later rotation the relay did not serve would not show here.",
    tests: ["src/__tests__/page.test.ts", "-t", "PINNED is conditional ON THE CARD"],
  },
  {
    name: "F3: the PINNED card treats the claimed time as the receipt's time",
    file: "src/labels.ts",
    find: "at the time this receipt claims — ${CLAIMED_TIME}.",
    replace: "at this receipt's time.",
    tests: ["src/__tests__/page.test.ts", "-t", "PINNED is conditional ON THE CARD"],
  },
  {
    name: "F3: the pinned rung says time-valid at the receipt's time",
    file: "src/ladder.ts",
    find: "          : `pinned — the key fits the time window at the time this receipt claims (completed_at, the signer's own claim) in this motebit's identity chain, as served by the relay${root}; when the receipt was issued is not proven`,",
    replace:
      "          : `pinned — the key was time-valid at the receipt's time in this motebit's identity chain, as served by the relay${root}`,",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "canonical legacy UUIDv7"],
  },
  {
    name: "F3: the KEY COMMITMENT card stops saying completed_at is a claim",
    file: "src/labels.ts",
    find: "${succession} This receipt's ${CLAIMED_TIME}. A key minted",
    replace: "${succession} A key minted",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "a record served for another motebit"],
  },
  {
    name: "F3: the honesty block says 'when it signed' for a key commitment",
    file: "src/honesty.ts",
    find: "        : \"That this key was still the motebit's key when the receipt was issued — completed_at is the signer's own claim, and rotation and revocation were not established.\",",
    replace:
      '        : "That this key was still the motebit\'s key when it signed — rotation and revocation not established.",',
    tests: [
      "src/__tests__/claimed-vs-proven.test.ts",
      "-t",
      "relay down → KEY COMMITMENT that says",
    ],
  },
  {
    name: "F3: the honesty block says 'dated before signing' after a complete scan",
    file: "src/honesty.ts",
    find: "only that no revocation memo naming it, at any date, was found on-chain.",
    replace: "only that no revocation memo dated before signing was found on-chain.",
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "a memo for another key"],
  },
  {
    name: "F3: did:key KEY COMMITMENT copy calls the id a hash of the key",
    file: "src/labels.ts",
    find: '    ? "the motebit_id encodes this signing key (a did:key)"',
    replace: '    ? "the motebit_id is a hash of this signing key"',
    tests: [
      "src/__tests__/claimed-vs-proven.test.ts",
      "-t",
      "relay down → KEY COMMITMENT that says",
    ],
  },
  {
    name: "F3: the claim field no longer marks completed_at as the signer's claim",
    file: "src/render.ts",
    find: 'field("completed (signer\'s claim)"',
    replace: 'field("completed"',
    tests: ["src/__tests__/claimed-vs-proven.test.ts", "-t", "canonical legacy UUIDv4"],
  },
  {
    name: "F3: llms.txt again says a memo is compared with the receipt's time",
    file: "public/llms.txt",
    find: ", whatever its date relative to the receipt's `completed_at`: that time is the signer's own claim, so a memo dated after it clears nothing.",
    replace: ", when it is dated at or before the receipt.",
    tests: ["src/__tests__/page.test.ts", "-t", "llms.txt"],
  },
];

function vitest(args) {
  return spawnSync("pnpm", ["exec", "vitest", "run", ...args], {
    cwd: APP,
    encoding: "utf8",
  });
}

// TAMPER_ONLY=<substring> runs only the entries whose name contains it (iteration aid;
// the full run is the gate).
const only = process.env.TAMPER_ONLY;
let failures = 0;
for (const t of only ? TAMPERS.filter((x) => x.name.includes(only)) : TAMPERS) {
  const path = join(APP, t.file);
  const original = readFileSync(path, "utf8");
  const count = original.split(t.find).length - 1;
  if (count !== 1) {
    console.error(`✗ ${t.name}: tamper text found ${count}× in ${t.file} — re-target this entry`);
    failures++;
    continue;
  }
  writeFileSync(path, original.replace(t.find, t.replace));
  try {
    const r = vitest(t.tests);
    const summary = /Tests\s+([^\n]+)/.exec(r.stdout)?.[1]?.trim() ?? "(no summary)";
    if (r.status === 0) {
      console.error(`✗ ${t.name}: tests stayed GREEN with the fix removed — ${summary}`);
      failures++;
    } else {
      console.log(`✓ red as expected: ${t.name} — ${summary}`);
    }
  } finally {
    writeFileSync(path, original);
  }
}

const restored = vitest(["src/__tests__/page.test.ts", "src/__tests__/claimed-vs-proven.test.ts"]);
if (restored.status !== 0) {
  console.error("✗ page / claimed-vs-proven tests are not green after restoring every file");
  failures++;
} else {
  console.log("✓ all fixes restored: page and claimed-vs-proven tests green");
}
process.exit(failures === 0 ? 0 : 1);
