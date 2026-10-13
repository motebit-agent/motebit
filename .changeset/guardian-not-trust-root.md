---
"@motebit/crypto": major
"@motebit/state-export-client": minor
---

**Security: a guardian named only by the identity file being verified no longer establishes binding.** `verifyKeyBindingAtTime` fell back to the presented file's own `guardian.public_key` whenever the caller passed no guardian. That guardian is signed only by the file's current key, which is the key a recovery link installs, so it proves nothing. An attacker who knew only a sovereign motebit's genesis **public** key could name their own guardian, sign a guardian-recovery link from the genesis key to their own key, and get `{ bound: true, sovereign: true }` from `verifyKeyBindingAtTime`, `true` from `verifyMigratingKeyBinding`, a bound result from `verifyIdentityBindingAnchored` (given an inclusion proof for that key), and `binding: "sovereign"` from `verifyReceiptDocument(text, { identity })`. No victim secret was needed.

The rule now: a guardian supplied only by the artifact being verified may be checked for signature integrity, but can never establish authority. The change is fail-closed by default. No flag, option or legacy mode restores the fallback.

- `@motebit/crypto`:
  - `verifyKeyBindingAtTime`: when the succession chain contains a guardian-recovery link and the caller passes no guardian, it returns `bound: false` with `guardianAuthority: "not_established"`. The links are still checked against the file's guardian, and that result is reported as `successionIntegrity`. The fourth parameter is renamed `trustedGuardianPublicKeyHex`. Its position and type are unchanged. It is the only guardian a recovery link is checked against for binding, and only a well-formed 32-byte hex value counts as supplied (`null`, `""` or malformed reads as `not_established`). The refusal covers every key of such a chain, including the genesis key and prefix keys reached by ordinary rotation before the recovery.
  - `KeyBindingResult` gains three optional fields that keep the properties apart: `genesisCommitment` (the id commits to the genesis key; a fact that authorizes nothing on its own), `successionIntegrity` and `guardianAuthority` (`"not_required" | "caller_trusted" | "not_established"`). Current authority is not established by any offline verifier, and no field claims it.
  - `verifyMigratingKeyBinding` gains an optional fourth parameter, `trustedGuardianPublicKeyHex`. The guardian in the presented file is never used.
  - `verifyIdentityBindingAnchored` renames its last parameter to `trustedGuardianPublicKeyHex`, with the same meaning.
  - The `verify()` identity path is unchanged: `succession.valid` still checks a recovery link against the file's own guardian. That is an integrity claim about the file, never a binding claim.
- `@motebit/state-export-client`: `verifyReceiptDocument` gains the option `trustedGuardianPublicKey`. Without it, a chain through a recovery link no longer lifts a receipt above `integrity-only`. The exception is a receipt that is sovereign on its own, because its key is the genesis key the id commits to (the receipt-alone check).
- receipt.computer (`@motebit/verify-web`, not published): no page grade changes. Since #1115 it grades only on its own guardian-stripped served-chain check and the receipt-alone check. The verifier's raw `binding` it receives moves lower for recovery chains, and the page does not grade on that value.

Tests: `packages/crypto/src/__tests__/guardian-not-trust-root.test.ts`, `packages/state-export-client/src/__tests__/receipt-document-guardian.test.ts` and `apps/verify/src/__tests__/receipt-computer-guardian-grades.test.ts`.

Tampers: `scripts/tampers/guardian-not-trust-root.ts` has seven entries, all red. Doctrine: `docs/doctrine/identity-binding-verification.md` § "A guardian named by the artifact is never a trust root".

## Migration

**Why major for `@motebit/crypto`.** A verification rule tightened, so previously accepted inputs now fail. `docs/doctrine/release-versioning.md` names that as a major trigger. The broken previously-valid caller is concrete: `verifyKeyBindingAtTime(file, key, t)`, or `verifyMigratingKeyBinding(id, key, file)`, on a legitimate identity whose chain runs through a guardian recovery and whose guardian is only in the file. That call returned bound (or `true`) and now returns `bound: false` (or `false`). The type surface change is additive, but the verdict change is the break. There is no deprecation window, because the old default is the vulnerability (the deprecation-lifecycle "forbidden-silent-compat" case).

**Why minor for `@motebit/state-export-client` (0.x).** Under 0.x semver a minor is the breaking-change signal (`^0.6.2` does not admit `0.7.0`). A major would promote the package to 1.0.0, which is a separate decision (`docs/doctrine/promoting-private-to-public.md`).

**Before:** the guardian came from the file being verified.

```ts
const r = await verifyKeyBindingAtTime(identityFile, receipt.public_key, receipt.completed_at);
// recovery chain + identityFile.guardian present  ->  { bound: true, sovereign: true }

const view = await verifyReceiptDocument(text, { identity: identityFile });
// -> binding: "sovereign"
```

**After:** pass a guardian you trust independently of the material you are verifying.

```ts
// pinnedGuardianHex: held on your own device, registered with you under the
// identity's key, or configured by your operator. NEVER identityFile.guardian.
const r = await verifyKeyBindingAtTime(
  identityFile,
  receipt.public_key,
  receipt.completed_at,
  pinnedGuardianHex,
);

const view = await verifyReceiptDocument(text, {
  identity: identityFile,
  trustedGuardianPublicKey: pinnedGuardianHex,
});

const ok = await verifyMigratingKeyBinding(
  motebitId,
  presentedKey,
  identityFile,
  pinnedGuardianHex,
);
```

If you have no independent guardian, leave the parameter out. A chain through a recovery link then reads as not bound, with `guardianAuthority: "not_established"` and `successionIntegrity` reporting whether the links' signatures hold. Do not copy `identityFile.guardian.public_key` into the parameter. That trusts whoever wrote the file, and it reopens the hole.

Unaffected: chains made only of ordinary rotations, and never-rotated identities.

Affected, and easy to miss:

- **Genesis-key receipts.** Unchanged through `verifyReceiptDocument` and `verifyMigratingKeyBinding`, which have the receipt-alone check. But `verifyKeyBindingAtTime(file, genesisKey, t)` and `verifyIdentityBindingAnchored` now return unbound when the chain contains a recovery link and no trusted guardian is passed.
- **Prefix keys.** For a chain genesis→k1 (ordinary)→k3 (recovery) with no trusted guardian, k1 at a time before the recovery goes from bound/sovereign to unbound, and a k1 receipt goes from `sovereign` to `integrity-only`. This is deliberately conservative; whether prefix keys may bind without the guardian is an open decision.
