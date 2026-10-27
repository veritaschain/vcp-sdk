# VCP SDK — offline core for VeritasChain Protocol v1.2

[日本語](README.ja.md)

**Version 0.1.0 — pre-release.** Python, TypeScript and MQL5 libraries for
producing and verifying [VeritasChain Protocol (VCP) v1.2](https://github.com/veritaschain/vcp-spec/tree/v1.2.0/spec/v1.2)
events offline: canonical hashing, Merkle trees, Ed25519 signatures and
verification with three-valued results.

> **Status and disclosure**
>
> * **First-party.** This SDK is written by VeritasChain Co., Ltd., which operates
>   the VeritasChain Standards Organization (VSO). It is not an external or
>   independent implementation and does not change VSO's disclosed count of
>   external implementations (zero).
> * **Not certified, not a conformance claim.** A `VALID` result from this
>   verifier means the checks it ran matched. It does not mean that the producing
>   system conforms to VCP or VAP.
> * **Pre-release.** The API can change before 1.0. Where VCP v1.2 is ambiguous
>   the SDK makes a choice; [INTERPRETATIONS.md](INTERPRETATIONS.md) lists those
>   choices and the SDK's own verification decisions, all that we are aware of.
>   Read it before comparing hashes with another implementation.
> * **Install from this repository only.** VSO has not published these packages
>   to PyPI or npm.

## What it does

| | Python | TypeScript | MQL5 |
|---|---|---|---|
| Canonical JSON (RFC 8785, with exact integers: INTERPRETATIONS.md I-4) | ✓ | ✓ | ✓ (no floating-point numbers) |
| EventHash (SHA-256; SHA3-256, BLAKE3 in Python/TS) | ✓ | ✓ | SHA-256 |
| RFC 6962 Merkle root, inclusion and consistency proofs | ✓ | ✓ | root, inclusion verification |
| Ed25519 event and root signatures | ✓ | ✓ | — (sign with `vcp seal`) |
| Event, batch, AnchorRecord builders | ✓ | ✓ | unsigned events (JSON Lines) |
| Three-valued verifier (event, batch, chain, inclusion) | ✓ | ✓ | — |
| Command line (`vcp`) | ✓ | — | — |

Verification reports one result per check:

| Result | Meaning |
|---|---|
| `VALID` | The check was performed and matched. |
| `INVALID` | The check was performed and a mismatch, or a malformed field, was shown. |
| `INDETERMINATE` | The check could not be performed with what was supplied: no trusted key, no external-anchor proof or verifier, unsupported algorithm, and so on. **Not a pass.** |

Checks are combined with the precedence INVALID > INDETERMINATE > VALID,
following VSO's unadopted [three-valued verification draft](https://github.com/veritaschain/vap-spec/blob/main/proposals/three-valued-verification/README.md).
A check the SDK does not perform is never reported as VALID: it is either
INDETERMINATE or named in the report's notes as not checked. A check that looks
at format only says so in its name (`anchor_timestamp_format`).

## What it does not do

* It does not contact anything. External anchoring (OpenTimestamps, an RFC 3161
  TSA, a blockchain, an attested database) is done by the caller; VCP v1.2
  section 6.3.3 requires it at every tier. To verify an anchor, pass your own
  `external_anchor_verifier`; otherwise the result is `INDETERMINATE`.
* It does not establish that a key belongs to the party named in an event. The
  caller supplies the keys it trusts.
* It does not show that recorded events are true, that every event that should
  have been recorded was recorded, or that a trading or AI decision was correct.
  Completeness is checked only relative to an anchored root, at anchor
  granularity.
* It runs after the fact. It does not stop, block or alter any trading or AI
  activity.
* It does not read COSE/SCITT envelopes, verify ECDSA, RSA or post-quantum
  signatures, check `Security.AnchorReference`, or validate events against the
  full JSON Schema.
* It is not an implementation of [vcp-sdk-spec](https://github.com/veritaschain/vcp-sdk-spec),
  which targets VCP v1.1 and the VeritasChain Cloud / Explorer API clients.

## Important differences from the VCP v1.2 example code

* **Merkle trees follow RFC 6962.** VCP v1.2 section 6.2.1 requires RFC 6962,
  but its example code duplicates odd nodes. Roots differ at every tree size that
  is not a power of two. A batch built the example way is reported as
  `INDETERMINATE` (`LEGACY_MERKLE_CONSTRUCTION`), not INVALID. See INTERPRETATIONS.md I-1.
* **Integers are hashed as their exact digits.** RFC 8785 treats numbers as
  binary64, which would round or reformat most nanosecond `TimestampInt` values.
  The SDK writes every integer exactly, so different integers never share a
  hash; an implementation that applies RFC 8785 to integers above 2^53 computes
  a different hash for such events. See I-4.
* **Signature coverage is narrow.** The AnchorRecord signature covers the root
  only, so `EventCount`, `FirstEventID`, `LastEventID` and `PolicyID` are checked
  against the supplied events, not against a signature. See I-6.

The [interoperability workplan and shared boundary fixtures](docs/INTEROPERABILITY_WORKPLAN.md)
exercise these choices in Python and TypeScript, including exact signature bytes,
unsigned anchor metadata, and unavailable external proof. They are first-party,
non-normative research fixtures; specification adoption and independent reproduction remain open.

## Install

Python 3.10+:

```bash
pip install "git+https://github.com/veritaschain/vcp-sdk.git@v0.1.0#subdirectory=python"
```

TypeScript (Node 20+, or a browser bundler):

```bash
git clone --branch v0.1.0 https://github.com/veritaschain/vcp-sdk.git
cd vcp-sdk/typescript && npm ci && npm run build
# then in your project:  npm install /path/to/vcp-sdk/typescript
```

MQL5: copy `mql5/Include/VeritasChain` to `MQL5/Include/`, and the scripts and
experts you want to `MQL5/Scripts/` and `MQL5/Experts/`. See [mql5/README.md](mql5/README.md).

## Quick start (Python)

```python
import veritaschain_vcp as vcp

key = vcp.generate_key()            # or vcp.SigningKey(seed) with a seed you keep secret
p = vcp.Producer(key, actor_id="ea-01", chain_id="ea-01-main",
                 policy_id="org.example:silver-v1", use_prev_hash=True)
p.create("INIT", {"VCP-GOV": {"AlgoID": "my-ea", "AlgoVersion": "1.4.0"}})
p.create("ORD", {"VCP-TRADE": {"Symbol": "USDJPY", "Side": "BUY", "Price": "151.230", "Quantity": "100000"}})

batch, record = p.close_batch()
# Anchor batch.merkle_root externally, then:
# record["AnchorTarget"] = {"Type": "PUBLIC_SERVICE", "Identifier": "opentimestamps.org", "Proof": "<proof>"}

report = vcp.verify_batch(batch.events, record, key.verify_key, require_sign_algo="ED25519")
print(report.status)            # INDETERMINATE until the external anchor is supplied and verified
for c in report.failed():
    print(c.name, c.status, c.reason)
```

Command line. Exit codes: 0 VALID (or success), 1 INVALID, 2 INDETERMINATE,
3 usage error, unreadable or malformed input, or a refusal by `vcp seal`. An
unexpected error inside a verifier is reported as an INDETERMINATE check
(`VERIFIER_ERROR`), so it exits with 2, or with 1 if another check was INVALID.

Private keys are read from a file or the `VCP_PRIVATE_KEY` environment
variable, never from the command line. On POSIX systems the key file must have
mode 0600; on Windows no ACL is checked, so restrict access to the file yourself.
An environment variable is inherited by every process started from that shell.

```bash
vcp keygen --out ea.key                       # writes the seed with mode 0600, prints the public key
vcp verify-batch events.jsonl --anchor anchor.json --public-key <base64>
vcp verify-chain events.jsonl
vcp seal unsigned.jsonl --private-key-file ea.key --out events.jsonl --anchor-out anchor.json
```

`vcp seal` checks every line before signing (structure, timestamps, the
EventHash the producer wrote, and each PrevHash link) and refuses the file if a
line fails. It signs every valid line the file contains, so protect the folder
the producer writes to. For a chain split across files, pass the previous file's
`last_event_hash` (printed by `vcp seal`) as `--prior-hash`, and line 1 must
link to it.

## Quick start (TypeScript)

```ts
import { Producer, generateKey, verifyBatch, toJson, parseJsonLines } from "@veritaschain/vcp";

const key = generateKey();
const p = new Producer(key, "svc-01", "svc-01-main", "org.example:silver-v1", { precision: "MILLISECOND" });
p.create("SIG", { "VCP-TRADE": { Symbol: "EURUSD", Price: "1.08310" } });
const { batch, record } = p.closeBatch();
const lines = batch.events.map(toJson).join("\n");          // bigint-safe JSON
const report = verifyBatch(parseJsonLines(lines), record, { publicKey: key.verifyKey, requireSignAlgo: "ED25519" });
console.log(report.status);
```

Parse event JSON with `parseJson` / `parseJsonLines`, not `JSON.parse`, which
rounds nanosecond timestamps. `nowNs()` in TypeScript has millisecond
resolution; pass `timestampNs` yourself if you need finer timestamps.

## How it was tested

| Area | Evidence |
|---|---|
| RFC 8785 | RFC 8785 Appendix B numbers and section 3.2 examples; 3,000 random documents against the [`rfc8785`](https://pypi.org/project/rfc8785/) Python package; 4,500 numbers against V8's `Number#toString`; integer vectors including 2^60, −2^63 and a collision pair (1791504000123456768 / …800) that must hash differently |
| Merkle | Certificate Transparency reference roots; roots, inclusion and consistency proofs identical to [transparency-dev/merkle](https://github.com/transparency-dev/merkle) for sizes 1–64 (`tools/merkle-crosscheck-go`); mutation tests |
| Ed25519 | RFC 8032 section 7.1 TEST 1–3; rejection of the 8 small-order key encodings, non-canonical encodings, keys with a torsion component, the identity-key forgery, a mixed-order-R signature and an S + L signature, in both languages |
| Hostile input | `test-vectors/hostile.json`: 114 malformed or adversarial inputs (wrong types, prototype-named fields, huge and deep values, line-separator tricks, bad timestamps, bad anchors, a tampered event next to each kind of malformed AnchorRecord field) with hand-written expected results. Both suites must produce every expected result and never raise |
| Cross-language | Python and TypeScript reproduce each other's canonical bytes, hashes and signatures byte for byte (`test-vectors/vectors.json`), and each verifies batches produced by the other, including timestamps that are exact in binary64 (`tools/crosslang/run.sh`). For every verifier case in both vector files, the TypeScript report must list the same checks, in the same order, with the same results and reasons, as the Python report |
| MQL5 | Compiled with MetaEditor under Wine, and the self-test run in the MetaTrader 5 terminal, by `tools/mql5/compile-and-selftest.sh` (the `mql5` CI workflow runs it). On 2026-10-25, MetaTrader 5 build 6283 on Wine 11.20: 0 errors and 0 warnings for the self-test and the example EA; self-test 199 passed, 0 failed. Not tested on Windows or with a logged-in account; the example EA was compiled, not run. `mql5/Scripts/VeritasChain/VCP_SelfTest.mq5` is generated from the same vectors and checks canonical output, hashes, Merkle roots and proofs, and the writer: line format, resume (including a Payload that contains EventHash keys), refusal of another chain and of an incomplete last line, and continuing a chain in a new file. Run it in your own terminal before use. |

The 12 batch and chain cases in `vectors.json` take their expected results from
the Python verifier and cover well-formed input. The expected results in the
hostile corpus are written by hand, so they do not come from either
implementation.

Run the tests:

```bash
cd python && pip install -e ".[test]" && pytest
cd typescript && npm ci && npm test
tools/crosslang/run.sh
```

## Repository layout

```
python/        Python package veritaschain-vcp (import veritaschain_vcp), CLI `vcp`
typescript/    TypeScript package @veritaschain/vcp
mql5/          VCP.mqh, self-test script, example EA
test-vectors/  vectors.json (known-good) and hostile.json (adversarial), shared by all three
tools/         vector generator, Ed25519 edge cases, Go Merkle cross-check, cross-language check
INTERPRETATIONS.md   the choices made where VCP v1.2 is ambiguous, and the SDK's verification decisions
```

## License and contact

Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).
Specification questions: standards@veritaschain.org. Security reports: see [SECURITY.md](SECURITY.md).
