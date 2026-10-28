# SDK → Explorer API → GUI evidence demo

**Non-normative, first-party integration example.** The workload is synthetic;
the Python SDK actually computes the event hashes, Ed25519 signatures, hash
chain, RFC 6962 Merkle root and inclusion proofs. No external anchor or successful
verification result is invented. This is not an independent implementation,
conformance assessment, certification, or a demonstration of live trading.

The producer/verifier baseline is SDK commit
[`5b94860d1244e36257f5682926a29192a91e7f9f`](https://github.com/veritaschain/vcp-sdk/tree/5b94860d1244e36257f5682926a29192a91e7f9f),
package version 0.1.0. It targets the published VCP v1.2.0 specification at
[`b23acb266f88df81d960d36d58fb64ceaa0dd5ed`](https://github.com/veritaschain/vcp-spec/tree/b23acb266f88df81d960d36d58fb64ceaa0dd5ed/spec/v1.2)
under the choices in [INTERPRETATIONS.md](../../INTERPRETATIONS.md). Adding this
example adopts no specification choice and changes no SDK verification rule.

## Cases and scope

| Case | Evidence | Explicit trust configuration | Local checks | Full SDK batch result |
| --- | --- | --- | --- | --- |
| `intact` | Three signed INIT/SIG/ORD events | Public demo event and root key | VALID | INDETERMINATE: no external anchor proof |
| `tampered` | Same batch with the order price changed after signing | Same public demo key | INVALID | INVALID |
| `missing-key` | Exactly the intact evidence bytes | No trusted event or root key | INDETERMINATE | INDETERMINATE |

“Local checks” means the batch verifier's checks except `external_anchor`, plus
the chain verifier's checks. This is an application display scope, not a new
normative result. The full SDK result and the external-anchor check must remain
visible. In particular, do not relabel the intact batch as fully VALID or pass a
callback that simply returns `true` to make it green.

For inclusion proofs, recompute the event hash from the supplied event before
checking its path. In the tampered case, a path over the **original claimed hash**
still demonstrates that original hash's inclusion; it does not validate the
changed payload. A root supplied in this bundle is not independently
authenticated merely because the bundle contains it.

## Files and trust boundary

`bundle.json` is the evidence transport, format `vcp-evidence-demo/1`. Its
`cases` array contains `id`, `title`, `description`, `events_jsonl`,
`anchor_record_json` and `inclusion_proofs`. A proof contains `event_id`, `index`,
`tree_size`, `event_hash`, `merkle_root` and the leaf-to-root `proof` hash array.
`event_hash` retains the `sha256:` prefix; the root and siblings are bare hex.
The bundle contains no trusted keys or stored verification results.

`trust.json`, format `vcp-evidence-demo-trust/1`, is **separate caller policy**.
Its `cases` object selects `actor_public_keys` and `anchor_public_key` for each
fixed case. The key is RFC 8032 section 7.1 TEST 1 public test material. Its seed
is openly documented in the generator; anyone can sign with it. Never use this
key as evidence of a person, organization, deployment or real event. An API must
load trust configuration separately and must not take keys from evidence as
automatically trusted.

The embedded JSON strings are intentional. Timestamps are nanosecond integers
larger than 2^53. Normal JSON transport can carry these **strings** unchanged;
parse the inner evidence with the SDK's strict, bigint-aware parser. Do not use
JavaScript `JSON.parse` on the event/anchor strings or convert them to rounded
numbers before checking a hash. The raw strings can be displayed or downloaded
without transformation.

An API should run verification afresh, preserving per-check reasons and notes.
The tests contain expected outcomes; those expectations are not evidence and
must not be returned as if verification had run.

## Regenerate and verify

From the repository root, with the Python and TypeScript development
dependencies installed:

```sh
PYTHONPATH=python/src python tools/generate_explorer_demo.py
PYTHONPATH=python/src python -m pytest python/tests/test_explorer_demo.py -q
npm --prefix typescript run build
node --test typescript/test/explorer-demo.test.mjs
git diff --exit-code -- examples/explorer-demo/bundle.json examples/explorer-demo/trust.json
```

The output is deterministic: timestamps, UUID randomness, payloads, signing key
and event order are fixed. The Python tests check regeneration and verification;
the TypeScript tests verify the same Python-produced evidence bytes, including
the changed payload, missing key and large-integer transport boundary. They
remain first-party tests.

The optional Explorer API integration uses explicit `VCP_EVIDENCE_BUNDLE`,
`VCP_EVIDENCE_TRUST` and `VCP_EVIDENCE_SDK_MODULE` paths. The last points to this
repository's built `typescript/dist/index.js`. The API and GUI are maintained
in [vcp-explorer-api](https://github.com/veritaschain/vcp-explorer-api) and
[vcp-explorer-gui](https://github.com/veritaschain/vcp-explorer-gui); consult their
demo setup instructions. Reading or checking this bundle requires no network
access, external account, production key or real trading system.

## Run an offline verification without a hosted API

The first-party [offline replay CLI](../../docs/EXPLORER_REPLAY_CLI.md)
recomputes all three cases using the local SDK, or compares a saved public API
response against local evidence and separately supplied trust configuration.
It does not rely on the hosted API's verdict or network availability. This is
**not** an independent implementation or proof of external anchoring.

~~~sh
npm --prefix typescript ci
npm --prefix typescript run build
node tools/replay_explorer_demo.mjs
~~~
