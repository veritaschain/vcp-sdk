# Changelog

## Unreleased

* Added a deterministic SDK → Explorer API → GUI evidence demo with Python-produced
  signed events, Merkle proofs, separate public-test-key trust configuration, and
  Python/TypeScript verification tests. Intact, tampered and missing-key cases
  preserve raw JSON and nanosecond integers. No external anchor is invented;
  the intact batch's full SDK result remains INDETERMINATE. This is non-normative
  first-party integration material, not certification or a new SDK release.
* MQL5 is now compiled and self-tested: `tools/mql5/compile-and-selftest.sh`
  installs MetaTrader 5 under Wine, compiles the self-test and the example EA
  with MetaEditor and runs the self-test in the terminal; the `mql5` CI workflow
  runs it. First run (2026-10-25, build 6283, Wine 11.20): 0 errors, 0 warnings;
  199 passed, 0 failed. No change to the MQL5 code.
* SECURITY.md: GitHub private vulnerability reporting is enabled.

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
