---
"@motebit/crypto": patch
"@motebit/state-export-client": patch
---

**A malformed identity file never throws and never binds.** `verifyKeyBindingAtTime` read `identity.succession ?? []` and then used it as an array: a `succession` that was a string threw `TypeError: chain.some is not a function`, an array holding `null` threw on `chain[0].old_public_key`, and an object or number was read as "no rotations", binding the genesis key on a history the file does not actually carry. Every wrapper inherited the throw, including `verifyMigratingKeyBinding` and `verifyIdentityBindingAnchored` (documented never to throw) and `@motebit/state-export-client` `verifyReceiptDocument` (documented "never throws on bad input").

- `@motebit/crypto`: a `succession` that is present but not an array of record objects, or an identity file with no `identity.public_key` string, now returns `bound: false` with a reason. Absent or `null` still means "never rotated".
- `@motebit/state-export-client`: `verifyReceiptDocument` contains each binding rung, so a rung whose check throws on an unreadable identity file simply does not lift the receipt; the ladder continues and the result stays at what the receipt's own signature proved.

Tests: `packages/crypto/src/__tests__/key-binding-malformed-succession.test.ts`, `packages/state-export-client/src/__tests__/receipt-document-malformed-succession.test.ts`; tampers `scripts/tampers/key-binding-malformed-succession.ts`.
