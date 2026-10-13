/**
 * Tamper check for the receipt.computer overclaim mitigation (cold review F-1,
 * F-2, F-3; round 2: B served-chain binding, D truthful copy, G unauthenticated
 * revocation). Each entry reverts ONE fix point and names the tests that must go
 * red. The script applies the tamper, runs those tests, demands a non-zero exit,
 * and restores the file. An entry whose `find` text is not present exactly once
 * is a hard error — a tamper that silently fails to apply would be a false green.
 *
 *   node apps/verify/scripts/tamper-overclaim.mjs
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
    find: '  if (v.binding === "revoked" || v.binding === "unverified") {',
    replace:
      '  if (v.binding === "revoked" || v.binding === "unverified" || v.binding === "sovereign") {',
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
    find: "and the chain is not shown to be committed in the operator's transparency log (the anchored rung).",
    replace:
      "it does not yet prove the chain is the operator's current, non-equivocable record (the anchored rung).",
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
    find: "      summary: `REVOCATION REPORTED (unauthenticated) — ${when}; who posted it was not checked — read ${sourceLabel(v.chainSource)}`,",
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
];

function vitest(args) {
  return spawnSync("pnpm", ["exec", "vitest", "run", ...args], {
    cwd: APP,
    encoding: "utf8",
  });
}

let failures = 0;
for (const t of TAMPERS) {
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

const restored = vitest(["src/__tests__/page.test.ts"]);
if (restored.status !== 0) {
  console.error("✗ page tests are not green after restoring every file");
  failures++;
} else {
  console.log("✓ all fixes restored: page tests green");
}
process.exit(failures === 0 ? 0 : 1);
