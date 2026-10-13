/**
 * @vitest-environment jsdom
 *
 * The REAL page path: index.html's body + main.ts (DOM wiring) + the real
 * verifier (@motebit/state-export-client / @motebit/crypto), with only the
 * network mocked. These are the display-layer safety properties from the
 * receipt.computer cold review (F-1, F-2, F-3): the page must never show a
 * positive claim stronger than its evidence.
 *
 *   F-3  a new input, a share-link change, or a verification exception CLEARS
 *        the previous verdict at once; an exception renders "Not verified".
 *   F-1  the receipt-alone genesis commitment never renders SOVEREIGN (no
 *        time-windowed succession check backs it).
 *   F-1  a revocation scan that hit the 200-signature page limit never renders ✓.
 *   F-2  evidence read only through Motebit's own RPC proxy never renders
 *        ANCHORED / "confirmed on-chain" / revocation ✓.
 *
 * Fixtures are minted with the real signer from the public demo seeds
 * (rc-review probe/mint.mjs); the relay declaration is signed by a demo key.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import INDEX_HTML from "../../index.html?raw";
import DECLARATION from "./fixtures/relay-declaration.json?raw";
import A4 from "./fixtures/A4-victim-sovereign.json?raw";
import C4 from "./fixtures/C4-delegation-null-signed.json?raw";
import C5 from "./fixtures/C5-delegation-string-signed.json?raw";
import C5B from "./fixtures/C5b-delegation-object-signed.json?raw";
import D4A from "./fixtures/D4a-retired-genesis-after-rotation.json?raw";
import D4A_CTX from "./fixtures/D4a-retired-genesis-after-rotation.ctx.json?raw";
import D5 from "./fixtures/D5-pinned.json?raw";
import D5_CTX from "./fixtures/D5-pinned.ctx.json?raw";
import D6A from "./fixtures/D6a-anchored.json?raw";
import D6A_CTX from "./fixtures/D6a-anchored.ctx.json?raw";

const FIXTURES: Record<string, string> = {
  "A4-victim-sovereign": A4,
  "C4-delegation-null-signed": C4,
  "C5-delegation-string-signed": C5,
  "C5b-delegation-object-signed": C5B,
  "D4a-retired-genesis-after-rotation": D4A,
  "D4a-retired-genesis-after-rotation.ctx": D4A_CTX,
  "D5-pinned": D5,
  "D5-pinned.ctx": D5_CTX,
  "D6a-anchored": D6A,
  "D6a-anchored.ctx": D6A_CTX,
};
const fixture = (name: string): string => {
  const text = FIXTURES[name];
  if (text === undefined) throw new Error(`no fixture ${name}`);
  return text;
};
const ctxOf = (name: string): MockCtx => JSON.parse(fixture(`${name}.ctx`)) as MockCtx;
const BODY = /<body>([\s\S]*)<\/body>/
  .exec(INDEX_HTML)![1]!
  .replace(/<script[\s\S]*?<\/script>/g, "");

interface MockCtx {
  readonly bundle?: unknown;
  readonly memos?: readonly string[];
  readonly rpcFail?: boolean;
  readonly relayDown?: boolean;
}

/** The fixture's receipt as a `#r=` share link (same encoding as fragment.ts). */
function linkHash(text: string): string {
  const min = JSON.stringify(JSON.parse(text));
  let bin = "";
  for (const b of new TextEncoder().encode(min)) bin += String.fromCharCode(b);
  return `#r=${btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

/** 200 newer anchor memos sitting in front of anything older (newest first). */
const FILLER_200 = Array.from(
  { length: 200 },
  (_, i) => `motebit:anchor:v1:${i.toString(16).padStart(64, "0")}:${i + 2}`,
);

const json = (body: unknown, status = 200): Response =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

let requests: string[] = [];
function mockNetwork(ctx: MockCtx): void {
  requests = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input : input.url,
    );
    requests.push(`${init?.method ?? "GET"} ${url.origin}${url.pathname}`);
    if (url.hostname === "relay.motebit.com") {
      if (ctx.relayDown) throw new TypeError("network down");
      if (url.pathname === "/.well-known/motebit-transparency.json") return json(DECLARATION);
      if (url.pathname.startsWith("/api/v1/identity/")) {
        return ctx.bundle !== undefined ? json(ctx.bundle) : json({ error: "not found" }, 404);
      }
      return json({}, 404);
    }
    if (init?.method === "POST") {
      // Any Solana JSON-RPC endpoint: honour getSignaturesForAddress `limit`, newest first.
      if (ctx.rpcFail) return json("down", 503);
      const req = JSON.parse(init.body as string) as { params: [string, { limit: number }] };
      const all = (ctx.memos ?? []).map((m, i) => ({
        signature: `tx${i}`,
        slot: 1,
        err: null,
        memo: `[1] ${m}`,
        blockTime: null,
      }));
      return json({ jsonrpc: "2.0", id: 1, result: all.slice(0, req.params[1].limit) });
    }
    throw new TypeError(`unexpected request ${url.href}`);
  });
}

// main.ts registers window listeners (hashchange); drop them between tests so a
// previous page instance never acts on this one.
const windowListeners: Array<[string, EventListenerOrEventListenerObject]> = [];
const realAdd = window.addEventListener.bind(window);

async function openPage(opts: { hash?: string; ctx?: MockCtx; rpc?: string } = {}): Promise<void> {
  document.body.innerHTML = BODY;
  history.replaceState(null, "", `/${opts.hash ?? ""}`);
  mockNetwork(opts.ctx ?? {});
  if (opts.rpc !== undefined) vi.stubEnv("VITE_SOLANA_RPC_URL", opts.rpc);
  vi.resetModules();
  await import("../main.js");
}

const container = (): HTMLElement => document.getElementById("result-container")!;
const grade = (): string | null => container().querySelector(".grade-badge")?.textContent ?? null;
const rung = (key: string): Element | null =>
  container().querySelector(`.proof > .ladder > [data-rung="${key}"]`);

/** Wait until the page shows a final verdict card or an explicit not-verified state. */
async function settled(): Promise<void> {
  await vi.waitFor(
    () => {
      const c = container();
      const done =
        c.querySelector(".result-card") !== null || /Not verified/.test(c.textContent ?? "");
      if (!done) throw new Error("not settled");
    },
    { timeout: 4000, interval: 20 },
  );
  // Let any in-flight run that settled the same tick finish its DOM write.
  await new Promise((r) => setTimeout(r, 30));
}

function typeIn(text: string): void {
  const input = document.getElementById("receipt-input") as HTMLTextAreaElement;
  input.value = text;
  input.dispatchEvent(new Event("input"));
}

/** Anything a positive verdict card shows. */
function showsPositiveVerdict(): boolean {
  const c = container();
  return (
    c.querySelector(".chip-ok") !== null ||
    c.querySelector(".tone-bound") !== null ||
    /SOVEREIGN|ANCHORED|PINNED|valid signature/.test(c.textContent ?? "")
  );
}

beforeEach(() => {
  vi.spyOn(window, "addEventListener").mockImplementation(((
    type: string,
    l: EventListenerOrEventListenerObject,
    o?: boolean | AddEventListenerOptions,
  ) => {
    windowListeners.push([type, l]);
    realAdd(type, l, o);
  }) as typeof window.addEventListener);
});

afterEach(() => {
  for (const [t, l] of windowListeners.splice(0)) window.removeEventListener(t, l);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("F-3: a previous verdict never outlives the input it was for", () => {
  for (const name of [
    "C4-delegation-null-signed",
    "C5-delegation-string-signed",
    "C5b-delegation-object-signed",
  ]) {
    it(`typing ${name} after the sample clears the card at once and ends in "Not verified"`, async () => {
      await openPage();
      await settled();
      expect(showsPositiveVerdict()).toBe(true); // the sample's card is up

      typeIn(fixture(name));
      // Synchronously — before the debounce, before any verification — the
      // sample's verdict is gone.
      expect(showsPositiveVerdict()).toBe(false);

      await settled();
      expect(showsPositiveVerdict()).toBe(false);
      expect(container().textContent).toContain("Not verified — could not check this receipt");
    });
  }

  it("navigating from one share link to a throwing one (hashchange) clears the old verdict", async () => {
    const a4 = fixture("A4-victim-sovereign");
    await openPage({ hash: linkHash(a4), ctx: { relayDown: true } });
    await settled();
    expect(showsPositiveVerdict()).toBe(true);

    location.hash = linkHash(fixture("C4-delegation-null-signed"));
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    expect(showsPositiveVerdict()).toBe(false);
    await settled();
    expect(showsPositiveVerdict()).toBe(false);
    expect(container().textContent).toContain("Not verified — could not check this receipt");
  });
});

describe("F-1: the receipt-alone genesis commitment is not SOVEREIGN", () => {
  it("the sample (offline) shows integrity + an original-key commitment, never SOVEREIGN", async () => {
    await openPage();
    await settled();
    expect(grade()).not.toBe("SOVEREIGN");
    expect(container().textContent).not.toMatch(/sovereign/i);
    expect(rung("binding")?.querySelector(".check-mark.ok")).toBeNull();
    expect(rung("integrity")?.querySelector(".check-mark.ok")).not.toBeNull();
    expect(container().textContent).toContain(
      "identity commitment matches the motebit's original key; rotation and revocation not established",
    );
  });

  it("a retired genesis key signing after rotation (chain served) is not SOVEREIGN, revocation not ✓", async () => {
    const name = "D4a-retired-genesis-after-rotation";
    await openPage({ hash: linkHash(fixture(name)), ctx: ctxOf(name) });
    await settled();
    expect(grade()).not.toBe("SOVEREIGN");
    expect(container().textContent).not.toMatch(/sovereign/i);
    expect(container().querySelector(".tone-bound")).toBeNull();
    expect(rung("binding")?.querySelector(".check-mark.ok")).toBeNull();
    expect(rung("revocation")?.querySelector(".check-mark.ok")).toBeNull();
  });
});

describe("F-1: a revocation scan that is truncated or failed is never ✓", () => {
  const INDEPENDENT_RPC = "http://localhost:8899";

  it("independent RPC, 200 signatures returned (page limit hit) → revocation not established", async () => {
    const name = "D5-pinned";
    await openPage({
      hash: linkHash(fixture(name)),
      ctx: { ...ctxOf(name), memos: FILLER_200 },
      rpc: INDEPENDENT_RPC,
    });
    await settled();
    expect(grade()).toBe("PINNED");
    const rev = rung("revocation")!;
    expect(rev.querySelector(".check-mark.ok")).toBeNull();
    expect(rev.textContent).toContain("not established");
    expect(rev.textContent).not.toContain("no on-chain revocation found");
  });

  it("a revocation memo beyond the 200 window is not hidden behind ✓", async () => {
    const name = "D5-pinned";
    const legacyHex = (JSON.parse(fixture(name)) as { public_key: string }).public_key;
    await openPage({
      hash: linkHash(fixture(name)),
      ctx: {
        ...ctxOf(name),
        memos: [...FILLER_200, `motebit:revocation:v1:${legacyHex}:1790000000500`],
      },
      rpc: INDEPENDENT_RPC,
    });
    await settled();
    expect(rung("revocation")?.querySelector(".check-mark.ok")).toBeNull();
    expect(rung("revocation")?.textContent).toContain("not established");
  });

  it("RPC failure → revocation not established, never ✓", async () => {
    const name = "D5-pinned";
    await openPage({
      hash: linkHash(fixture(name)),
      ctx: { ...ctxOf(name), rpcFail: true },
      rpc: INDEPENDENT_RPC,
    });
    await settled();
    expect(rung("revocation")?.querySelector(".check-mark.ok")).toBeNull();
    expect(rung("revocation")?.textContent).toContain("not established");
  });

  it("control: an independent, complete scan (under the page limit) may show ✓", async () => {
    const name = "D5-pinned";
    await openPage({ hash: linkHash(fixture(name)), ctx: ctxOf(name), rpc: INDEPENDENT_RPC });
    await settled();
    expect(rung("revocation")?.querySelector(".check-mark.ok")).not.toBeNull();
  });
});

describe("F-2: evidence read only through Motebit's RPC proxy is labelled, never ANCHORED or ✓", () => {
  it("the default RPC is the operator proxy: an anchor found there does not render ANCHORED", async () => {
    const name = "D6a-anchored";
    await openPage({ hash: linkHash(fixture(name)), ctx: ctxOf(name) });
    await settled();
    expect(requests.some((r) => r.startsWith("POST https://api.motebit.com/v1/solana-rpc"))).toBe(
      true,
    );
    expect(grade()).not.toBe("ANCHORED");
    const text = container().textContent ?? "";
    expect(text).not.toMatch(/confirmed on-chain|anchored on-chain|whose root is on-chain/i);
    expect(text).toContain("via Motebit's RPC proxy (not independently confirmed)");
    expect(rung("revocation")?.querySelector(".check-mark.ok")).toBeNull();
  });

  it("the proxy reporting no revocation is not a ✓", async () => {
    const name = "D5-pinned";
    await openPage({ hash: linkHash(fixture(name)), ctx: ctxOf(name) });
    await settled();
    const rev = rung("revocation")!;
    expect(rev.querySelector(".check-mark.ok")).toBeNull();
    expect(rev.textContent).toContain("via Motebit's RPC proxy (not independently confirmed)");
  });

  it("control: the same anchor through an independent RPC may render ANCHORED", async () => {
    const name = "D6a-anchored";
    await openPage({
      hash: linkHash(fixture(name)),
      ctx: ctxOf(name),
      rpc: "http://localhost:8899",
    });
    await settled();
    expect(grade()).toBe("ANCHORED");
  });

  it("the page copy does not claim the browser queries Solana itself", () => {
    expect(INDEX_HTML).not.toContain("and Solana, with its public key");
    expect(INDEX_HTML).toContain("Motebit's RPC proxy");
    expect(INDEX_HTML).not.toMatch(/so it verifies <em>sovereign<\/em>/);
  });
});
