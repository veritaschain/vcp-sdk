# @veritaschain/vcp (TypeScript)

Offline core for VeritasChain Protocol (VCP) v1.2 events for Node 20+ and
browsers: canonical hashing (RFC 8785 with exact integers), RFC 6962 Merkle
trees, Ed25519 and a verifier with three-valued results. Same rules, checks and
reason codes as the Python package; both run `test-vectors/hostile.json`.

Development source with package version 0.1.0, first-party (VeritasChain Co., Ltd. / VSO), not certified;
a VALID result is not a conformance claim. Install from the repository; VSO has
not published this package to npm. See the repository README and
INTERPRETATIONS.md: https://github.com/veritaschain/vcp-sdk

Use the [pinned development-source installation guide](https://github.com/veritaschain/vcp-sdk#install).
The historical `v0.1.0` tag lacks the later replay-input and Merkle-proof input
fixes. Package metadata still reports `0.1.0`; the documented commit identifies
the corrected snapshot, not a new tagged release.

* `TimestampInt` and other large integers are `bigint`. Use `parseJson` /
  `parseJsonLines` to read events and `toJson` to write them; `JSON.parse`
  rounds nanosecond timestamps and `JSON.stringify` cannot write `bigint`.
* Ed25519 verification is cofactorless and rejects small-order and
  non-canonical public keys (INTERPRETATIONS.md I-5); it does not use
  `@noble/curves`' own `verify`, which is cofactored.
* `nowNs()` has millisecond resolution.
* Build: `npm ci && npm run build`. Test: `npm test`.
