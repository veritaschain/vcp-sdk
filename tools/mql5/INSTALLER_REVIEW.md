# MetaTrader installer integrity gate

## Review status — 2026-11-02

The bootstrap installer needs an operator-reviewed SHA-256 before the Wine job
can run. **No production installer digest has been approved or fabricated in this
change.** Both the historical download URL and the current official link returned
HTTP 403 in the review environment; no downloaded Windows executable was run.
No publisher-issued checksum was found in the official pages reviewed below.

The `mql5` workflow reads the GitHub repository variable `MT5_SETUP_SHA256` and
fails before installing Wine when it is missing or malformed. The shell script
also checks the pin, installer bytes and Authenticode verification before starting
Wine. Its negative-control tests use synthetic non-executable bytes and stub
commands; they do not validate a real MetaQuotes installer or MQL5 compilation.

## Acquisition-only workflow mode — 2026-11-03

The existing manual `mql5` workflow accepts `mode=installer-review` on the
review branch. A separate Windows job downloads only the fixed official HTTPS
URL, refuses redirects, requires Windows `Valid` embedded Authenticode status
and the expected MetaQuotes Ltd signer, and records certificate details and
SHA-256 in the job summary and log. It never runs the installer, stores no
repository variable and removes the temporary file. Its result still requires
operator review before a pin is configured.

In this mode the normal compile job intentionally exits 3 before checkout or
Wine, so acquisition cannot satisfy the compiler check. The default `compile`
mode and push/PR runs retain the reviewed-pin and signature gates. Run that
separate compile/self-test after approving a digest. The local retry on
3 November still returned HTTP 403; no approved digest is recorded here.

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
  documents Authenticode verification.

The CI action pins were resolved from the official `actions/*` Git tag endpoints
on 2026-11-02; the existing major versions were preserved:

| Action tag | Commit |
| --- | --- |
| [checkout v4](https://api.github.com/repos/actions/checkout/git/ref/tags/v4) | `11d5960a326750d5838078e36cf38b85af677262` |
| [setup-python v5](https://api.github.com/repos/actions/setup-python/git/ref/tags/v5) | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| [setup-node v4](https://api.github.com/repos/actions/setup-node/git/ref/tags/v4) | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| [setup-go v5](https://api.github.com/repos/actions/setup-go/git/ref/tags/v5) | `40f1582b2485089dde7abd97c1529aa768e1baff` |
