/**
 * Tamper check for the receipt.computer overclaim mitigation (cold review F-1,
 * F-2, F-3). Each entry reverts ONE fix point and names the tests that must go
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
    name: "F-1: receipt-alone sovereign passes through instead of becoming a key commitment",
    file: "src/assess.ts",
    find: '    case "sovereign":\n      binding = "key-commitment";\n      break;\n',
    replace: "",
    tests: ["src/__tests__/page.test.ts", "-t", "SOVEREIGN"],
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
    find: '      if (evidence?.source === "independent") {',
    replace: "      if (true) {",
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
