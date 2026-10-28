# Offline replay of the Explorer evidence demo

First-party, non-normative replay of three synthetic cases. Not independent
implementation, external-anchor verification, production attestation, certification,
or a legal compliance decision. The deployed API/GUI and original signed fixture
are not changed by this hardening. No secrets or live AILEX data are used.

## Run from a reviewed checkout (Node.js 22+)

```sh
npm --prefix typescript ci --ignore-scripts --no-audit
npm --prefix typescript run build
node tools/replay_explorer_demo.mjs
node tools/replay_explorer_demo.mjs --case tampered --json
node tools/replay_explorer_demo.mjs --api-response ./complete-api-response.json --json
```

Install/build requires dependencies; replay of a local file after setup makes no
network request. Use the complete API JSON response, not only an Event JSONL file.
Signed inner JSON is preserved exactly; the SDK strict parser keeps large integers.
Trust comes from a separately selected local `examples/explorer-demo/trust.json`.
The signing key is public RFC 8032 test material and authenticates no real identity.

Optional direct HTTPS probe:

```sh
node tools/replay_explorer_demo.mjs --api-url \
  https://veritaschain-evidence-demo.kamimura0000.chatgpt.site/v1/evidence-demo/cases/intact/verification
```

## Input and error contract

Select exactly one of `--bundle`, `--api-response`, or `--api-url` (default: local
bundle). Input mode is separate from the decoded value: JSON null, arrays,
primitives, bad JSON and unavailable responses NEVER fall back to local fixtures.
Repeated options and conflicting modes are usage errors. Files must be regular
files within 2 MiB (trust: 64 KiB); network responses are streamed with a 2 MiB
limit and a 15-second timeout. HTTP errors read at most a 512-byte diagnostic
prefix. Redirects, URL credentials, non-JSON media, invalid UTF-8 and duplicate
JSON keys are rejected. HTTPS is required except explicit loopback HTTP.

Without `--case`, a bundle must contain all three known IDs once each. With
`--case`, a subset may be selected, but duplicates/unknown IDs are still rejected.
Malformed keys/proofs and duplicate proof IDs or event IDs are input errors.
Missing inclusion evidence is INDETERMINATE, not a demonstrated mismatch.
An actual wrong root/binding, altered payload, or extra proof for an absent event
is INVALID. This aligns with the pinned portable API's covered checks.

## Results are separate claims

| Field | Meaning |
| --- | --- |
| `local_status` / `overall_status` | Recomputed cryptographic checks in the stated scopes |
| `matches_expected_outcome` | Verdict pair agrees with the case's expected result |
| `fixture_bytes_match` | Signed inner strings exactly match the checked-out reference; detached proofs match structurally |
| `matches_api_claim` | Recomputed aggregate verdicts agree with the supplied API claims (response mode only) |
| `matches_fixed_demo` | Deprecated compatibility alias for outcome equality only, NOT fixture identity |

The reference fixture is the repository checkout, not authenticated merely by its
presence. Pin/review the source revision. All supplied cases are recomputed even
when the fixture differs. A fixed-demo success requires outcome equality AND
fixture equality AND, in response mode, API aggregate equality. It does not
validate every API display string or authenticate the server's source code.

Expected local/full pairs: intact VALID/INDETERMINATE; tampered INVALID/INVALID;
missing-key INDETERMINATE/INDETERMINATE. Exit 0 means the fixed-demo expectations
matched, not that all cases were VALID. Exit 1 means a fixture/outcome/API-claim
mismatch; exit 2 means malformed input, transport, or usage error. Neither an
input error nor an HTTP 403 is reported as a cryptographic INVALID result.

## Tests and reproduction

```sh
node --test typescript/test/explorer-replay*.test.mjs
# Optional full per-check comparison with a reviewed API checkout:
VCP_EVIDENCE_API_CORE=/absolute/api/src/evidence/core.ts \
  node --test typescript/test/evidence-adapter-parity.integration.mjs
```

The parity workflow pins API commit `c3d67ab2467a55e017f652b38a2b89c3f4a7cee7`.
It executes that actual portable TypeScript core and the actual SDK, comparing
normal, missing-proof, bad-binding, extra-proof, payload-change and missing-key
results including each check's reason/scope/subject. Duplicate proofs are
rejected by both. This is first-party cross-adapter testing, not a third-party
implementation. Source archives and commit/hash receipts are retained for 30
days in CI; source at the Git commit remains the permanent reproduction input.

See [the bounded three-client public probe](PUBLIC_EVIDENCE_PROBE.md) for live
HTTP checks. A descriptive User-Agent identifies the tool honestly, not a
promise of host access. The historical HTTP 403/1010 remains an observation,
not a diagnosis fixed by this patch. No host policy/DNS changes are made.
