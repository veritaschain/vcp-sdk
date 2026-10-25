# Interpretations of VCP v1.2 made by this SDK

The SDK targets the published **VCP v1.2.0** specification
([tag `v1.2.0`, commit `b23acb2`](https://github.com/veritaschain/vcp-spec/tree/b23acb266f88df81d960d36d58fb64ceaa0dd5ed/spec/v1.2)).
In several places that text is ambiguous or contradicts itself. This file lists
the choices the SDK makes in those places, and the verification decisions that
are the SDK's own rather than the specification's: all of them that we are
aware of. If you find behaviour that is not covered here, please report it.

None of these choices is adopted by VSO change control. Two related VSO
proposals are open and unadopted:
[integrity errata draft](https://github.com/veritaschain/vcp-spec/blob/main/proposals/integrity-2026-10-24/technical-errata-draft.md)
and [numeric-field inventory](https://github.com/veritaschain/vcp-spec/tree/main/proposals/numeric-fields-2026-10-25).
The SDK does **not** implement the unadopted byte-contract candidate in
`proposals/integrity-2026-10-24/byte-contract-candidate-v0`. If VSO adopts a
different rule, a later SDK version will follow it and say so in the changelog.

The Python and TypeScript packages are meant to apply every rule below in the
same way. Both test suites run the shared corpus `test-vectors/hostile.json`
(malformed and adversarial inputs with hand-written expected results), and for
every verifier case in it and in `vectors.json` the TypeScript suite checks that
its report lists the same checks, in the same order, with the same results and
reasons, as the Python report. Detail texts may differ. Inputs outside the
corpora may still expose a difference; please report it.

## I-1 Merkle trees follow RFC 6962, not the section 6.2.1 example code

Section 6.2.1 says construction "MUST follow RFC 6962", and the example code
under it duplicates the last node of an odd level. RFC 6962 section 2.1 (kept in
RFC 9162 section 2.1) splits at the largest power of two below the leaf count and
never duplicates a node. The SDK follows the RFCs:

```
leaf  = SHA-256(0x00 || decoded EventHash)     (32 bytes, section 6.2.1: bytes.fromhex(h))
node  = SHA-256(0x01 || left || right)
split = largest power of two smaller than n
```

* Roots differ from the example code at tree sizes 3, 5, 6, 7 and 9–15 (of
  1–16); checked up to 299 leaves, they differ at every size that is not a
  power of two and agree at powers of two. The example code also gives
  `[e0,e1,e2]` and `[e0,e1,e2,e2]` the same root; the RFC construction does not.
* Inclusion and consistency proofs follow RFC 9162 sections 2.1.3 and 2.1.4.
  Proofs are a list of hashes ordered from leaf to root; index and tree size
  determine the sides. The section 6.2.3 `{"hash", "position"}` format is not produced.
* If an AnchorRecord root, or an event's `Security.MerkleRoot`, matches the
  example construction but not the RFC construction, the verifier reports it as
  `INDETERMINATE` with reason `LEGACY_MERKLE_CONSTRUCTION`, not as `INVALID`: the
  data has not been shown to be altered, it was built under the other
  construction, which this SDK does not verify. A batch built that way is
  therefore INDETERMINATE overall (unless something else is INVALID).
* As in RFC 9162, every tree is consistent with the empty tree: a consistency
  proof from size 0 is empty and accepted for any roots.
* The SDK's output was compared with the Certificate Transparency reference
  roots and with [transparency-dev/merkle](https://github.com/transparency-dev/merkle)
  (`tools/merkle-crosscheck-go`): roots, inclusion proofs and consistency proofs
  are identical for every tree size from 1 to 64.

## I-2 EventHash string forms

* `compute_event_hash` / `computeEventHash` return the bare lowercase hex digest,
  as the section 6.1.1 example does.
* `Security.EventHash` is written as `sha256:<64 hex>`, the form the v1.2 event
  schema describes for production values. Only the SHA-256 prefix appears in the
  published material, so SHA3_256 and BLAKE3 hashes are written as bare hex.
* Parsing accepts both forms for SHA-256, and upper- or lowercase hex digits
  (output is always lowercase). A `sha256:` prefix with a different `HashAlgo`
  is reported as `INVALID` (`HASH_FORMAT_MISMATCH`).

## I-3 PrevHash in the hash input

When an event carries `Security.PrevHash`, the hash input is
`JCS(Header) + JCS(Payload) + <previous EventHash as bare lowercase hex>`
(section 6.1.2), whatever form `Security.PrevHash` is written in. The all-zero
value means "no chain", as in section 6.1.2, and is treated like an absent PrevHash.

## I-4 Numbers: integers are written exactly

RFC 8785 serialises every number as an IEEE 754 binary64 value. The v1.2 event
schema carries `TimestampInt` as a JSON integer of nanoseconds and says 64-bit
precision must be preserved. Most such values are not exactly representable in
binary64 (around 2^60 the spacing between doubles is 256), and for some that are
representable RFC 8785 prints different digits (2^60 becomes
`1152921504606847000`). Applying RFC 8785 literally would therefore round, reject
or reformat nanosecond timestamps.

The SDK's rule, the same in Python, TypeScript and MQL5:

* **An integer is written as its exact decimal digits.** In Python that is an
  `int`; in TypeScript a `bigint` (the strict parser returns `bigint` for every
  integer literal outside ±(2^53 − 1)) or a safe-integer `number`; in MQL5 a `long`.
* **A floating-point number is written as RFC 8785 specifies**
  (ECMAScript `Number#toString`), **except** that a float with an integral value
  of magnitude in [2^53, 10^21) is rejected (`CanonicalizationError`, reported
  as `INDETERMINATE` / `CANONICALIZATION_UNSUPPORTED`). Its RFC 8785 form is a
  plain digit string that could equal the digits of a different integer, so
  accepting it would let two different values share one hash.

With this rule, different numeric values never have the same canonical form.
For integers up to 2^53 in magnitude, and for all other floats, the output is
exactly the RFC 8785 output.

* **Consequence:** an implementation that applies RFC 8785 to integers above
  2^53 computes a different EventHash for such an event, or refuses it. When an
  event contains such an integer, the verifier adds a note to its report.
* `strict_integers=True` / `{ strictIntegers: true }` (and `strict` in the
  canonicaliser) applies RFC 8785 to integers as well: an integer binary64
  cannot represent exactly is rejected, and others are written in RFC 8785 form.
* Integer fields accept any JSON number with an integral value (`0.0` for
  `SequenceNum`), as JSON Schema's `integer` type does. Such a float is
  canonicalised as a float: `0.0` hashes like `0`, while `1.8e18` is rejected
  under the rule above.
* Floating-point formatting was checked against RFC 8785 Appendix B, against
  V8's `Number#toString` for 4,500 values, and against the `rfc8785` Python
  package for 3,000 random documents. VCP section 4.2.2 requires financial
  values as decimal strings; the MQL5 builder has no floating-point numbers at all.

## I-5 What is signed, and how signatures are verified

* **Event signature:** Ed25519 over the ASCII bytes of the bare lowercase hex
  EventHash. VCP v1.2 section 6.3.1 requires every event to be signed but shows
  only root signing; the event form is VCP v1.0 section 6.2.2
  (`event_hash.encode()`), which v1.2 does not replace.
* **Merkle root signature:** Ed25519 over the 32 decoded root bytes (v1.2
  section 6.3.1, `bytes.fromhex(merkle_root)`).
* **Verification rule** (the same in Python and TypeScript):
  - a public key must be a canonical encoding of a point in the prime-order
    subgroup other than the identity (`[L]A` is the identity, `A` is not of
    small order); otherwise it is rejected and the signature check is
    `INDETERMINATE` (`KEY_NOT_ESTABLISHED`). This rejects the identity point,
    under which `R = identity, S = 0` would verify any message, the other
    small-order points, and points with a small-order (torsion) component, for
    which cofactored and cofactorless verifiers can decide differently. RFC 8032
    does not require the subgroup check; every key produced by RFC 8032 key
    generation passes it;
  - `S` must be below the group order L;
  - the check is cofactorless: `encode([S]B − [k]A)` must equal the R bytes.
    Python uses OpenSSL (through `cryptography`), which applies this check;
    TypeScript implements it with `@noble/curves` point arithmetic rather than
    noble's own `verify`, which is cofactored.
  The test vectors include RFC 8032 section 7.1 TEST 1–3, the eight small-order
  key encodings, non-canonical encodings, keys with a torsion component, the
  identity-key forgery, a signature whose R has a small-order component, and an
  `S + L` signature.
* The event signature is checked against the **recomputed** EventHash, not the
  value in `Security.EventHash`. An event changed after signing therefore gives
  both `HASH_MISMATCH` and `SIGNATURE_MISMATCH`; if the hash cannot be
  recomputed, the signature check is `INDETERMINATE` (`HASH_NOT_RECOMPUTED`).
* Signatures and keys in base64 must be standard base64 with padding, in
  canonical form (no non-zero padding bits).
* Only `ED25519` is implemented. `ECDSA_SECP256K1`, `RSA_2048`, `DILITHIUM2` and
  `FALCON512` are reported as `INDETERMINATE` (`ALGORITHM_UNSUPPORTED`), unless the
  caller passes `require_sign_algo="ED25519"` / `requireSignAlgo: "ED25519"`, in
  which case any other SignAlgo is `INVALID` (`ALGORITHM_MISMATCH`).
  `PQCSignature` is not verified. A signature carried in a COSE_Sign1 envelope
  (SCITT encoding) is not read.
* When the caller passes one key (not a per-ActorID map) and no separate anchor
  key, the AnchorRecord signature is checked with that same key; a note says so
  when that signature was actually verified.

## I-6 What each check covers, and what it does not

* `EventHash` covers `Header` and `Payload` only (section 6.1.1). A top-level
  `PolicyIdentification` block and the `Security` object are outside it; the
  verifier says so in a note when `PolicyIdentification` is present, and reports
  `INVALID` if its `PolicyID` differs from `Header.PolicyID`.
* The event signature covers the EventHash only. `Security.MerkleRoot` and
  `MerkleIndex` are not signed; batch verification checks them against the tree
  it rebuilds. If either is missing on an event, its placement in the batch is
  not checked and the batch is `INDETERMINATE` (`event_merkle_fields`,
  `MISSING_FIELD`); VCP v1.2 section 6.4.1 makes them REQUIRED from v1.1.
* `Security.AnchorReference` is **not checked**; the report says so in a note.
* The AnchorRecord signature covers the root only. `EventCount`, `FirstEventID`,
  `LastEventID` and `PolicyID` are not covered by it; batch verification checks
  them against the supplied events (`anchor_binding`). `Timestamp` is checked
  for format only (a non-negative integer), in the check named
  `anchor_timestamp_format`; its value is not checked against anything.
* A root and an inclusion proof do not fix the tree size: the same path can
  verify for more than one size. With VCP v1.2 the size (`EventCount`) is not
  signed, so `verify_inclusion_proof` reports `root_authenticity` as
  `INDETERMINATE`. If the caller says it authenticated the root and size
  (`root_authenticated=True`), that check is omitted and a note records that the
  SDK did not perform it.
* The SDK does not contact anchor targets. Without a caller-supplied
  `external_anchor_verifier`, the external anchor is `INDETERMINATE`. If the
  verifier raises, the result is `INDETERMINATE` and the error is noted.
* Completeness is shown only relative to an anchored root, at anchor
  granularity. An event that was never included in a batch, or never recorded,
  is not detectable by these checks.

## I-7 Formats, units and other verification decisions

* `TimestampInt` and `AnchorRecord.Timestamp` are nanoseconds since the Unix
  epoch (the schema states this for `TimestampInt`; the specification gives no
  unit for the AnchorRecord field).
* `TimestampISO` is written in UTC with `Z` and 3, 6 or 9 fractional digits
  (section 1.5.4). On input, any RFC 3339 form with 0–9 fractional digits and a
  `Z` or numeric offset is accepted (years 0001–9999, no leap second); the
  instant it denotes must agree with `TimestampInt` at the precision the ISO value
  is written with. Digits must be ASCII.
* `Security.Version` is written as `"1.1"`, as in the section 6.4 schema example.
* `Security.MerkleRoot` and `AnchorRecord.MerkleRoot` are bare lowercase hex
  (section 6.2.2 `tree.root.hex()`; section 6.3.3 "Hex-encoded root").
* `AnchorReference` defaults to the Merkle root, which identifies the
  AnchorRecord that carries it. Callers can pass their own reference.
* A missing `HashAlgo` is treated as `SHA256`, the section 1.5.2 default, with a
  note. A `HashAlgo` (or any other optional Security field) that is present but
  not a string, including `null`, is `INVALID` (`BAD_FORMAT`).
* `EventType` must be one of the 27 values in the v1.2 event schema; any other
  value is `INVALID` (`UNKNOWN_EVENT_TYPE`). `EventID` must be a UUID; its
  version is not checked (the schema accepts any RFC 9562 UUID; UUIDv7 is
  required only at Gold and Platinum).
* `AnchorTarget.Type` outside `BLOCKCHAIN`, `TSA`, `DATABASE`, `PUBLIC_SERVICE`,
  or a `Proof` that is present but not a string, is `INVALID`. An empty or absent
  `Proof` is `INDETERMINATE` (`MISSING_ANCHOR_PROOF`).
* Chains: SequenceNum must increase by one within the supplied events (a gap is
  `INVALID`). An INIT event at the start of the supplied events, without a
  PrevHash, is a chain start (`VALID`) when no prior hash is given; if a prior
  hash is given, that first link is `INDETERMINATE` (`CHAIN_NOT_USED`). Other
  events without a PrevHash give an `INDETERMINATE` link. A prior hash that is
  not a 32-byte hex digest makes only the first link `INDETERMINATE`
  (`PRIOR_HASH_MALFORMED`); the other checks still run, so a gap later in the
  chain is still `INVALID`.
* The structure check covers the required Header fields and their types and the
  types of the Security fields used. It is not a full JSON Schema validation of
  the v1.2 event schema (Payload module names and field types are not checked).
* JSON input is parsed strictly by both packages: duplicate keys, `NaN`,
  numbers outside binary64 range, a byte-order mark, nesting deeper than 128
  levels and integer literals longer than 4,300 digits are rejected. JSON Lines
  are split on `\n` only (a trailing `\r` is removed); U+2028 and other Unicode
  separators are ordinary characters.
* An unexpected exception inside a verifier adds an `INDETERMINATE` check with
  reason `VERIFIER_ERROR`. Checks completed before it are kept, so a report that
  already holds an `INVALID` check stays `INVALID`. The command line exits with
  the report's code (2, or 1 if a check is `INVALID`) in that case, and with 3
  for a usage error, unreadable or malformed input, or a refusal by `vcp seal`.
* `verify_inclusion_proof` / `verifyInclusionProof` accept any non-negative
  integer index and tree size (TypeScript: a safe-integer `number`, or a
  `bigint` for larger values). Only the value `True` / `true` for
  `root_authenticated` / `rootAuthenticated` omits the `root_authenticity` check.
* `FirstEventID` and `LastEventID` in an AnchorRecord must be strings equal to the
  first and last event's `EventID`; a missing value on either side is a binding
  mismatch.
* Error events: VCP v1.2 section 3.2.1 makes `ErrorDetails.Severity` and
  `ErrorDetails.ErrorMessage` REQUIRED and shows `ErrorDetails` as a top-level
  member of the event, which the v1.2 event schema does not allow (no extra
  top-level members; Payload members must be `VCP-*` modules). The SDK's example
  EA therefore writes `ErrorDetails` inside the module that carries the event
  (`VCP-TRADE.ErrorDetails` for ERR_REJECT) and also sets the schema's
  `VCP-TRADE.RejectReason`. The verifier does not check `ErrorDetails`.

## Result values

Results are `VALID`, `INVALID` or `INDETERMINATE`, combined with the precedence
INVALID > INDETERMINATE > VALID. The values follow the unadopted VSO discussion
draft [`vap-spec/proposals/three-valued-verification`](https://github.com/veritaschain/vap-spec/blob/main/proposals/three-valued-verification/README.md)
(revision 0.1). The reason codes (`HASH_MISMATCH`, `KEY_NOT_ESTABLISHED`,
`LEGACY_MERKLE_CONSTRUCTION` and so on) are this SDK's and are not registered
identifiers. `INDETERMINATE` is not a pass.
