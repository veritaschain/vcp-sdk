# veritaschain-vcp (Python)

Offline core for VeritasChain Protocol (VCP) v1.2 events: RFC 8785 canonical
hashing, RFC 6962 Merkle trees, Ed25519 signatures and a verifier with
three-valued results (VALID / INVALID / INDETERMINATE). Includes the `vcp`
command line.

Pre-release 0.1.0, first-party (VeritasChain Co., Ltd. / VSO), not certified;
a VALID result is not a conformance claim. See the repository README and
INTERPRETATIONS.md: https://github.com/veritaschain/vcp-sdk

```bash
pip install "git+https://github.com/veritaschain/vcp-sdk.git@v0.1.0#subdirectory=python"
```

Modules: `jcs` (canonical JSON), `hashing` (EventHash), `merkle`, `signing`,
`timeutil` (UUIDv7, timestamps), `producer` (events, batches, AnchorRecords),
`verify` (three-valued checks), `jsonio` (strict JSON loading), `cli`.
