# MetaTrader installer integrity gate

## Review status — 2026-11-03

The current official bootstrap installer was obtained without execution and
verified on both Windows and Linux in
[review run 41610090279](https://github.com/veritaschain/vcp-sdk/actions/runs/41610090279)
at commit `233ef09f19bd89cec882e2ee0e2d990e75b1133e`. Both systems obtained the
same 22,902,352 bytes. The exact installer and signing-certificate hashes are
recorded below. Local HTTP 403 responses and the earlier certificate-name denial
are historical review attempts, not the current acquisition status.

The production shell gate now pins the reviewed signer certificate with a literal,
read-only DER SHA-256 and native `osslsigncode -require-leaf-hash` verification.
It does not match publisher identity by searching certificate-subject text, and
there is no environment override for the signer pin. The installer's separate
`MT5_SETUP_SHA256` remains an operator-reviewed repository variable: missing or
malformed values stop the workflow before installing Wine, and byte mismatches
stop the shell script before any Wine process. Acquisition outputs never set it.

**Acquisition is not evidence of MQL5 compilation or self-test success.**
Compiler/self-test results are recorded separately in
[PR #8 checks](https://github.com/veritaschain/vcp-sdk/pull/8/checks) for their exact
source commits. The acquisition jobs did not execute the installer, and review
mode intentionally failed the compiler check before checkout or Wine. The
synthetic tests described below do not validate real MQL5 compilation.

## Observed certificate evidence — 2026-11-03

[Acquisition run 41608661890, job 125824758297](https://github.com/veritaschain/vcp-sdk/actions/runs/41608661890/job/125824758297)
ran the workflow at commit `c7671660cbe5a7c2ae49937b147d4e1273aaccfa`.
At `2026-11-03T09:09:09.0235759Z`, it downloaded 22,902,352 bytes from the fixed
official URL without redirects. Windows reported `Valid` and `Authenticode`.
The following values are the observed certificate fields, not inferred names:

| Field | Observed value |
| --- | --- |
| Subject | `CN=MetaQuotes Ltd., O=MetaQuotes Ltd., S=Lemesos, C=CY` |
| Issuer | `CN=Sectigo Public Code Signing CA E36, O=Sectigo Limited, C=GB` |
| Serial number | `008ED92F8A2233EEF06D24CC1D66D18277` |
| SHA-1 certificate thumbprint | `5A64A7AED24C33DED342D01D01FA5286F06DA6DC` |
| Validity | `2026-02-10T00:00:00Z` to `2029-02-09T23:59:59Z` |
| Timestamp subject | `CN=Certum Timestamp 2026, O=Asseco Data Systems S.A., C=PL` |

The old policy expected `MetaQuotes Ltd` and `L=Limassol`; it therefore denied
this certificate. The Windows acquisition policy requires the entire observed
subject, issuer, serial number and thumbprint exactly, together with native
signature validation. The subsequent successful run produced this evidence:

| Evidence | Verified value |
| --- | --- |
| Installer SHA-256 | `c8c0a73f86c58974df62fb48f8256a099d6698518cf2defc2b3f169773729e22` |
| Signer DER certificate SHA-256 | `c46c2889219dc55761cee7dad37457776ad2829b41880f4c2b0cdab19270f684` |
| Windows acquisition time | `2026-11-03T09:19:57.8899194Z` |
| Linux verification time | `2026-11-03T09:20:22.439943+00:00` |
| Installer size on both systems | 22,902,352 bytes |
| Linux CA-bundle SHA-256 | `e05a523d99de77c6b1f2c7b7c3af502c8378f29e6e8484358ec55f96b0972ad6` |

[Windows job 125829521773](https://github.com/veritaschain/vcp-sdk/actions/runs/41610090279/job/125829521773)
reported native `Valid` / `Authenticode`, the exact certificate identity above,
and both hashes.
[Linux job 125829735139](https://github.com/veritaschain/vcp-sdk/actions/runs/41610090279/job/125829735139)
used `osslsigncode 2.8` with the default CA bundle
`/etc/ssl/certs/ca-certificates.crt`. With the reviewed DER hash it exited 0 and
reported `Leaf hash match: ok`, signer-chain verification, signature CRL
verification, and timestamp signature/CRL verification. With an all-zero leaf
hash it exited 1 and reported `Leaf hash match: failed`; its computed leaf hash
matched the independently recorded Windows DER hash. No trust, timestamp, CRL,
or verification-time override was used. These are observations of that run;
later verification retains the native verifier's default behavior.

The actual Linux signer subject was
`/C=CY/ST=Lemesos/O=MetaQuotes Ltd./CN=MetaQuotes Ltd.`. It is recorded for audit
context; the production identity check uses the exact leaf-certificate hash.

## Acquisition-only workflow mode

The existing manual `mql5` workflow accepts `mode=installer-review` on the
review branch. A Windows job downloads only the fixed official HTTPS URL, refuses
redirects, verifies the signature and exact reviewed certificate identity, and
records certificate details and SHA-256 in the job summary and log. Its digest
outputs feed only a dependent Linux acquisition job; they do not configure any
repository variable or feed the normal compile job.

The Linux job downloads the same official URL without redirects, requires the
same installer bytes as Windows, and runs the distribution's `osslsigncode verify`
with `-require-leaf-hash sha256:<Windows-verified certificate DER hash>`. That
native option binds verification to the actual signing certificate rather than a
subject string somewhere in the certificate chain. The job records the complete
verification output and requires a deliberately wrong leaf hash to fail. The
successful cross-platform result above supports the fixed production signer pin.
The production installer digest remains separately configured by an operator;
review-mode outputs cannot become normal compilation inputs automatically.

Both jobs remove their temporary downloads and never execute the installer or
Wine. Their evidence still requires operator review before an installer pin is
configured. In review mode the normal compile job intentionally exits 3 before
checkout or Wine, so acquisition cannot satisfy the compiler check. The default
`compile` mode and push/PR runs retain the reviewed-pin and signature gates. Run
that separate compile/self-test after reviewing the signer and installer pins.

## Review and record a pin

1. Obtain the current installer through the link on the
   [official download page](https://www.metatrader5.com/en/download).
2. Verify the Authenticode signature and certificate trust chain with
   `osslsigncode verify -in mt5setup.exe -require-leaf-hash sha256:<reviewed-signer-DER-SHA256>`.
   Require a successful exit code using the exact reviewed signer hash above.
   A different signing certificate requires a separate evidence review and code
   update; no subject-text or missing-option fallback is permitted. Do not
   execute the file during this review.
3. Compute `sha256sum mt5setup.exe` and record the complete digest, retrieval time,
   effective URL, file size, signer details and reviewer approval. Prefer a
   publisher-authenticated digest if one becomes available.
4. Set `MT5_SETUP_SHA256` to that reviewed digest for local use or in the GitHub
   repository's Actions variables. Review any subsequent digest change separately.
   Do not obtain the expected digest dynamically from the same download in CI.

A locally computed pin detects later byte changes; it is not itself a publisher
attestation. The mandatory signature gate supplies a separate signer/trust check.
The endpoint is mutable, so a publisher update safely stops the job until the new
file has been reviewed. Cached installer bytes are rechecked on every run.

Twelve synthetic entrypoint regressions exercise the file and signer gates
without network access, executable installers or real Wine processes. The
verifier stub requires the exact native leaf-hash option and reviewed value;
dropping that binding fails the positive regression. Wrong signer hashes remain
blocked even with expected subject text, and an environment value cannot
replace the literal signer pin.

The installer is a web bootstrapper. It downloads additional terminal components,
and the terminal can update itself. This gate does **not** pin the complete
MetaTrader/Wine toolchain or attest an existing Wine prefix; use an isolated prefix
and treat compiler reproducibility as a separate check.

## Primary references

- [MetaTrader 5 official download page](https://www.metatrader5.com/en/download)
  linked the `download.terminal.free` Windows installer at review time.
- [Official installation guide](https://www.metatrader5.com/en/terminal/help/start_advanced/installation)
  describes its bootstrap downloads and unattended `/auto` installation.
- [osslsigncode project](https://github.com/mtrojnar/osslsigncode)
  documents Authenticode verification. The [2.8 implementation](https://github.com/mtrojnar/osslsigncode/blob/2.8/osslsigncode.c)
  applies `-require-leaf-hash` to the actual signing certificate and retains
  signature and trust validation.

The CI action pins were resolved from the official `actions/*` Git tag endpoints
on 2026-11-02; the existing major versions were preserved:

| Action tag | Commit |
| --- | --- |
| [checkout v4](https://api.github.com/repos/actions/checkout/git/ref/tags/v4) | `11d5960a326750d5838078e36cf38b85af677262` |
| [setup-python v5](https://api.github.com/repos/actions/setup-python/git/ref/tags/v5) | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| [setup-node v4](https://api.github.com/repos/actions/setup-node/git/ref/tags/v4) | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| [setup-go v5](https://api.github.com/repos/actions/setup-go/git/ref/tags/v5) | `40f1582b2485089dde7abd97c1529aa768e1baff` |
