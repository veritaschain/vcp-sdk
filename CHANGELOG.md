# Changelog

## 0.1.0 — 2026-10-25 (pre-release)

First release. Targets VCP v1.2.0 (vcp-spec tag `v1.2.0`, commit `b23acb2`).

* Python package `veritaschain-vcp` with the `vcp` command line.
* TypeScript package `@veritaschain/vcp` (Node 20+, browsers).
* MQL5 library `VCP.mqh`, generated self-test script and example EA (not compiled in CI).
* Shared test vectors (`vectors.json`) and a hostile-input corpus (`hostile.json`)
  with hand-written expectations, run by both test suites.
* Cross-checks against RFC 8785/8032 vectors, Certificate Transparency roots,
  transparency-dev/merkle and the `rfc8785` package.
* Interpretations of ambiguous VCP v1.2 text, and the SDK's own verification
  decisions, are listed in INTERPRETATIONS.md (I-1 to I-7).

Changes made before release after three rounds of pre-publication review,
commissioned by VeritasChain Co., Ltd. and carried out by an AI assistant (not an
independent review):

* integers are canonicalised as exact digits in all three languages (an earlier
  draft let two different integers share a hash);
* Ed25519 verification is the same in Python and TypeScript and rejects
  small-order keys and keys with a torsion component;
* checks that are not performed are no longer reported as VALID, and the
  format-only AnchorRecord timestamp check is named `anchor_timestamp_format`;
* verifiers return a report instead of raising on hostile input, and an
  unexpected error no longer hides checks completed before it (an earlier draft
  could turn a tampered batch into INDETERMINATE);
* a malformed prior hash no longer hides a sequence gap;
* the CLI no longer accepts private keys as arguments; `vcp seal` gained
  `--prior-hash` for chains split across files;
* the MQL5 writer reads and writes bytes, resumes from the last line's own
  Security object, refuses a file whose last line is incomplete or belongs to
  another chain, detects short writes, and can continue a chain in a new file;
  the example EA writes one file per UTC day.
