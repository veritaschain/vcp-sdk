# veritaschain-vcp (Python)

Offline core for VeritasChain Protocol (VCP) v1.2 events: RFC 8785 canonical
hashing, RFC 6962 Merkle trees, Ed25519 signatures and a verifier with
three-valued results (VALID / INVALID / INDETERMINATE). Includes the `vcp`
command line.

Development source with package version 0.1.0, first-party (VeritasChain Co., Ltd. / VSO), not certified;
a VALID result is not a conformance claim. See the repository README and
INTERPRETATIONS.md: https://github.com/veritaschain/vcp-sdk

Install the reviewed development snapshot below, which includes the later
replay-input and Merkle-proof input fixes. The historical `v0.1.0` tag does not
include those fixes. This is not a new release; the package version remains
`0.1.0`, so `--force-reinstall` also replaces an existing same-version install.
See the [repository installation guide](https://github.com/veritaschain/vcp-sdk#install)
for the snapshot's scope and other languages.

```bash
python -m pip install --force-reinstall "git+https://github.com/veritaschain/vcp-sdk.git@8eadded87e4f4e46d011835b2ba9a874b91c916d#subdirectory=python"
```

Modules: `jcs` (canonical JSON), `hashing` (EventHash), `merkle`, `signing`,
`timeutil` (UUIDv7, timestamps), `producer` (events, batches, AnchorRecords),
`verify` (three-valued checks), `jsonio` (strict JSON loading), `cli`.
