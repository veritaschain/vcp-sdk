# MetaTrader installer integrity gate

## Review status — 2026-11-03

The bootstrap installer needs an operator-reviewed SHA-256 before the Wine job
can run. **No production installer digest has been approved or fabricated in this
change.** Local acquisition attempts returned HTTP 403. A later download-only
GitHub-hosted Windows run obtained the installer and verified its native
Authenticode signature, then correctly failed the legacy subject-name policy.
It did not execute the installer or calculate an approved file pin.

The `mql5` workflow reads the GitHub repository variable `MT5_SETUP_SHA256` and
fails before installing Wine when it is missing or malformed. The shell script
also checks the pin, installer bytes and Authenticode verification before starting
Wine. Its negative-control tests use synthetic non-executable bytes and stub
commands; they do not validate a real MetaQuotes installer or MQL5 compilation.

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
this certificate. The acquisition policy now requires the entire observed subject,
issuer, serial number and thumbprint exactly, while still requiring native Windows
signature validation. A successful new review will record the certificate's DER
SHA-256 and the installer's SHA-256. Neither value is claimed here yet.

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
Linux trust check and exact output format remain unverified until this job runs.
The production Linux subject guard is left unchanged pending that evidence; a
subsequent reviewed change must pin the observed DER SHA-256 with the native
leaf-hash option before normal compilation.

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
   `osslsigncode verify -in mt5setup.exe`. Require a successful exit code and the
   expected MetaQuotes Ltd signer. Do not execute the file during this review.
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
