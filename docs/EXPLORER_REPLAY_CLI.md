# Offline replay of the Explorer evidence demo

**Scope:** First-party, non-normative verification of **three synthetic cases**.
This is not an independent implementation, production attestation, external-anchor
verification, completeness proof, certification or regulatory conformity finding.

The public Explorer is at https://veritaschain.org/explorer/app/#/evidence-demo .
Its verification endpoint may be blocked by host-level access controls for
non-browser HTTP clients. A historical Python HTTP 403 response contained
Cloudflare error **1010**. This is an access-control outcome, **not** a VCP
cryptographic INVALID. Browser success does not prove universal CLI access.

## No network required: replay the pinned evidence

Use a reviewed checkout of https://github.com/veritaschain/vcp-sdk .
The originally deployed demo SDK source was
70240a45fc83d38c3b4282ff886afd4dbbb9e006.
This CLI was added later, so review this CLI's changes before using it.

With Node.js 22+ and npm installed:

~~~sh
npm --prefix typescript ci
npm --prefix typescript run build
node tools/replay_explorer_demo.mjs
node tools/replay_explorer_demo.mjs --json
node tools/replay_explorer_demo.mjs --case tampered
~~~

The CLI loads examples/explorer-demo/bundle.json and a **separate**
examples/explorer-demo/trust.json from the checkout. It never trusts a public
key supplied by the evidence without separate caller configuration. The
fixture's Ed25519 key is publicly known RFC 8032 test material.

Expected outcomes:

| Case | Local checks | Full evidence |
| --- | --- | --- |
| intact | VALID | INDETERMINATE |
| tampered | INVALID | INVALID |
| missing-key | INDETERMINATE | INDETERMINATE |

The CLI recomputes event hashes, signatures, chain checks and Merkle inclusion
from the **actual supplied event payload** using the local TypeScript SDK.
It checks detached proof bindings to event IDs, positions and batch root.
A missing external proof stays INDETERMINATE. It **does not independently
implement** cryptographic primitives: the SDK and CLI are both first-party.

Exit status 0 means replay agrees with the fixed demonstration, **not** that
all events are VALID. Exit 1 signals a mismatch with the fixed demo outcome
or API claim. Exit 2 means input, network or usage error.

## Compare with a saved public API response

Save the **complete JSON response**, not only the Event JSONL or AnchorRecord,
from a browser or trusted client at:

~~~text
https://veritaschain-evidence-demo.kamimura0000.chatgpt.site/v1/evidence-demo/cases/intact/verification
~~~

Then run:

~~~sh
node tools/replay_explorer_demo.mjs --api-response ./intact-response.json
~~~

This recomputes from the response's evidence.events_jsonl,
evidence.anchor_record_json, and evidence.inclusion_proofs, and compares
the local and overall verdicts to the API's claims. It uses the locally
supplied trust.json, not keys inferred from the evidence. A forged
API success verdict will be rejected.

A direct HTTP probe is also available:

~~~sh
node tools/replay_explorer_demo.mjs --api-url \
  https://veritaschain-evidence-demo.kamimura0000.chatgpt.site/v1/evidence-demo/cases/intact/verification
~~~

A host-level 403, including Cloudflare error 1010, is reported as a transport
problem and does not change the result of the offline replay. Do not disguise
client identity to defeat access controls. Use the checked-out fixture, a
saved browser response or a deliberately supported alternate deployment.

## Trust and evidence boundaries

- Deterministic test vectors, not records of a real trade.
- The key is public and authenticates no real-world identity.
- Retain the raw signed inner JSON strings. Nanosecond timestamps exceed
  JavaScript's safe integer range; the SDK strict parser preserves them.
- Hash and signature equality checks relationships in data, not the truth
  of events or that every required event was observed.
- No third-party anchor, transparency-service registration or VCP/VAP
  conformance is established.
- Pin all relevant Git commits when reporting a reproduction. The public
  host and the local fixture can evolve independently.
