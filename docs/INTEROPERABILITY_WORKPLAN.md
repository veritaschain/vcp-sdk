# Interoperability verification workplan

Status: non-normative research and internal verification workplan. No VSO change-control adoption is implied.

The SDK's existing [INTERPRETATIONS.md](../INTERPRETATIONS.md) describes implementation-specific choices. The fixtures below record current SDK behavior; they do not settle the canonical representation of integers larger than 2^53, Merkle construction and proof encoding, or the signed bytes and authenticated metadata for events and anchors. Normative adoption and any migration remain specification work under the existing change-control process. This work introduces no new governance rule and changes no runtime, public API, version, or existing signed record.

## Internal fixture coverage

[interoperability-boundaries.json](../test-vectors/interoperability-boundaries.json) is a shared, versioned first-party fixture set consumed by the [Python tests](../python/tests/test_interoperability_boundaries.py) and [TypeScript tests](../typescript/test/interoperability-boundaries.test.mjs).

| Area | Executable expectations | Scope |
| --- | --- | --- |
| Numeric boundaries | Literal canonical bytes for 2^53−1, 2^53+1, −(2^53+1), and 2^60 | Current exact-integer interpretation (I-4), not an RFC 8785 or adopted VCP decision |
| Merkle boundary | Frozen roots for three leaves and four leaves with a duplicated final leaf; the roots differ | Current RFC 6962 construction (I-1); proof encoding and adoption remain open |
| Signature byte input | Frozen Ed25519 signatures over the ASCII lowercase hex digest for an event and the decoded 32 bytes for a root; exchanging the signatures fails | Current I-5 interpretation, with the same digest used to isolate the byte representation |
| Unsigned anchor metadata | EventCount or PolicyID changes retain a VALID root signature but cause INVALID anchor binding; the overall report remains INVALID despite absent external proof | Comparison with supplied events is separate from signature coverage (I-6) |
| Anchor timestamp | Another non-negative Timestamp passes the format-only check and leaves the root signature valid | The timestamp value is not authenticated; the report retains that limitation |
| Unavailable external evidence | Absent target, absent proof, and synthetic proof text with no verifier remain INDETERMINATE with explicit reason codes | No network calls, real external anchor evidence, or successful external-verification claim |

Expected canonical strings and report outcomes are handwritten. Hash expectations are calculated with Python `hashlib` over the stated bytes; new signatures are calculated directly with `cryptography`, without importing the SDK. The fixture includes a public RFC 8032 test seed for deterministic signing tests. It is for tests only. The anchor example uses small integers to isolate signature and metadata behavior from the large-integer question.

These calculations and both SDK implementations are first-party work. Using a separate calculation path or cryptographic library does not constitute separately authored implementation reproduction or external validation. `VALID`, `INVALID`, `INDETERMINATE`, and the reason codes here describe SDK-local results; they are not newly adopted normative identifiers.

## Remaining work before an interoperability claim

| Work item | State |
| --- | --- |
| Shared boundary bytes, roots, signatures, and expected check results | Implemented as internal regression fixtures in both languages |
| Specification decisions and migration/versioning for existing signed records | Open; this fixture work adopts no normative choice |
| Separately authored third-party reproduction against an agreed specification and versioned vectors | Open; two first-party language implementations do not satisfy this item |
| Broader proof encoding, external anchor evidence, and unsupported verification steps | Outside this fixture increment; existing limitations remain documented in INTERPRETATIONS.md |

Unresolved specification decisions remain open even when an internal check is VALID. A missing or unsupported verification step remains INDETERMINATE in the affected check; a demonstrated mismatch makes the combined result INVALID. A cryptographic check does not establish that the underlying event was true, that unrecorded events did not occur, or that an implementation is conformant or certified.

## Focused test commands

From the repository root, with the development dependencies installed:

```sh
PYTHONPATH=python/src python -m pytest python/tests/test_interoperability_boundaries.py -q
npm --prefix typescript run build
node --test typescript/test/interoperability-boundaries.test.mjs
```
