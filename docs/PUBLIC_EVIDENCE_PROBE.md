# Public Evidence Demo probe

This is a **first-party, read-only diagnostic**, not an independent reproduction,
production guarantee, certification, or external-anchor proof. It changes no
host policy, deployed API, signing key, published fixture, or normative VCP rule.

## Run

From a reviewed, pinned SDK checkout, with Python 3.10+, Node 22 and curl:

```sh
npm --prefix typescript ci --ignore-scripts --no-audit
npm --prefix typescript run build
python3 tools/test_public_evidence_probe.py -v
python3 tools/probe_public_evidence.py --output /tmp/vcp-public-probe-new
```

The output directory must not exist. Network access is needed for installation
and the public probe, but not the transport unit tests or the ordinary offline
replay after setup. The probe accepts only the documented public HTTPS origin
or literal 127.0.0.1 HTTP with an explicit port for local testing. No credentials,
secret variables, browser impersonation, retries or redirects are used.

## What is checked

For **each** of Python urllib, curl and Node fetch, request:

1. `/health`
2. `/v1/evidence-demo/cases`
3. `/v1/evidence-demo/cases/intact/verification`
4. `/v1/evidence-demo/cases/tampered/verification`
5. `/v1/evidence-demo/cases/missing-key/verification`

Each successful response must be JSON with `Cache-Control: no-store`. For the
three verification cases the case identity, expected verdicts and original
signed Event JSONL / AnchorRecord strings must match the checked-out fixture;
inclusion proofs must match structurally. The captured response is then replayed
by the local SDK through `replay_explorer_demo.mjs`, with separate local trust.
A matching aggregate alone is insufficient: different signed bytes cannot pass
as the fixed fixture just because they happen to yield the same verdict.

Two additional Python GET requests check explicit CORS allowance of
`https://veritaschain.org` and application rejection of `https://example.invalid`.
The latter must return `origin_not_allowed`, not merely an unrelated hosting
403. Neither case may advertise credential sharing. This does not emulate
browser enforcement, preflight handling, or every possible Origin value.

| Fixed case | Local checks | Full evidence |
| --- | --- | --- |
| intact | VALID | INDETERMINATE |
| tampered | INVALID | INVALID |
| missing-key | INDETERMINATE | INDETERMINATE |

Each run makes 17 public requests at most, with bounded response bodies (256 KiB),
timeouts, and no retries. The workflow has a ten-minute job limit. Exit 0 means
all probe expectations matched, including the deliberately INVALID tampered
case. Exit 1 means at least one HTTP/contract/replay test failed; exit 2 indicates
a setup error. None of these exit codes alone is a VCP evidence verdict.

## Artifacts and CI

`summary.json` records UTC observation time, actual checkout commit, response
status, selected headers, body hashes, and local replay results. Accepted
verification responses are retained for follow-up replay. Credentials and
cookies are neither supplied nor retained. Transport errors do not invent
cryptographic results. The observations are first-party and timestamped by the
runner, not authenticated timestamp receipts.

The `Public evidence API probe` workflow runs on relevant internal PRs/main
changes and manual dispatch; it has **no scheduled recurrence**. It tests
Ubuntu 24.04 and macOS 14 runners and retains artifacts for 30 days. Both are
GitHub-hosted environments, **not two independent operators** or independent
third-party implementations. Success does not prove universal reachability,
a stable service commitment, or current browser GUI operation.

A live-host failure is intentionally red; do not mask it by returning saved
success responses or reclassifying network failures as SDK INVALID. The SDK's
ordinary offline test workflow remains separate. Distinguish a build/setup
failure, transport rejection, contract mismatch and cryptographic replay failure
when reviewing CI.

## HTTP 403 / Cloudflare 1010

The historical Python probe in site PR #164 received HTTP 403 / error 1010;
previous browser observations do not establish CLI compatibility. Cloudflare's
primary documentation describes this as blocking based on the client's browser
signature and says the site owner controls the policy:

https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/

A descriptive `VCP-Evidence-Probe/0.1` User-Agent identifies this application
honestly; it is not browser impersonation, a guaranteed fix, or proof of the
host's specific rule configuration. The referenced page does not itself
prescribe a custom-domain migration. Neither host policy nor DNS is modified
by this probe. If legitimate clients remain blocked, the authorized hosting
operator must inspect its own rules or approve an alternate supported endpoint;
do not disable protections for an entire site merely to turn this test green.

Track public-host compatibility in
https://github.com/veritaschain/vcp-explorer-api/issues/26 . Preserve historical
observations and append new run URLs rather than retroactively replacing the
original rollout manifest. A two-runner first-party test does not close the
separate need for an independent external reproduction.
