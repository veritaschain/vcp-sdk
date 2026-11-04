# Wallet authorization evidence demo / ウォレット認可証跡デモ

**An optional, non-normative, first-party research example.** This demo shows why
a correctly signed audit record can contain evidence of an authorization
mismatch, or insufficient evidence to decide authorization. It uses the real
Python SDK's `verify_event`; it does not change that API or the meaning of its
`VALID` result. No VCP/VAP conformance, certification, production deployment, or
real incident reproduction is claimed.

The saved records contain synthetic wallet evidence in hash-covered
`Payload.ExperimentalWalletEvidence.Bundle`. `ExperimentalWalletEvidence` is
example data, **not a registered VCP payload module or a normative schema
extension**. The existing `SYS_AUDIT` event type is used. The SDK checks record
structure, timestamp agreement, EventHash, and the recorder signature. The
separately pinned VAP experiment checks the wallet evidence inside that record.

**任意の非規範・研究用サンプルです。** 実際のSDKによる記録の整合性検証と、
別の実験的検証器による認可・実行内容・委譲状態の検証を分けて表示します。
SDKが `VALID` を返しても、承認との矛盾が確認されれば認可は `INVALID`、
承認資料が不足すれば認可は `INDETERMINATE` になります。後者は「承認が
存在しなかった」という証明ではありません。既存SDKの不具合修正ではなく、
その検証範囲を維持した上での追加サンプルです。

## Run locally

Requires Python 3.10+ and the SDK's Python dependencies. Install from this
checkout if needed:

```sh
python -m pip install -e ./python
```

From the SDK repository root, replay only the saved SDK records:

```sh
python examples/wallet-authorization-demo/demo.py
```

With no companion specified, the actual SDK checks still run. All four wallet
claims are `INDETERMINATE` with `COMPANION_NOT_AVAILABLE`, and the illustrative
admission decision is `DENY`. The demo never substitutes a successful wallet
verdict for a missing implementation.

To also run the canonical wallet evidence verifier, obtain a **local** checkout
of [`veritaschain/vap-spec`](https://github.com/veritaschain/vap-spec) containing
`experiments/wallet-authorization-evidence/`, with source bytes matching
[`companion-lock.json`](companion-lock.json). This example pins the immutable
[source commit `7bdec510e3ed1f15a8362d30516acd7b161b9987`](https://github.com/veritaschain/vap-spec/tree/7bdec510e3ed1f15a8362d30516acd7b161b9987/experiments/wallet-authorization-evidence),
not a moving branch. For a new sibling checkout:

```sh
git clone --no-checkout https://github.com/veritaschain/vap-spec.git ../vap-spec
git -C ../vap-spec checkout --detach 7bdec510e3ed1f15a8362d30516acd7b161b9987
```

Then run:

```sh
python examples/wallet-authorization-demo/demo.py --vap-spec ../vap-spec
python examples/wallet-authorization-demo/demo.py --vap-spec ../vap-spec --case approval_mismatch
```

The loader checks the SHA-256 of both `wallet_evidence.py` and `fixtures.py`
before importing either, then compiles and executes exactly those verified
bytes. It neither reloads them from the path nor executes a cached `.pyc` or an
unverified `sys.modules` entry. An explicitly supplied checkout with missing or
mismatched files fails with exit code 2; it does not fall back silently. The
demo makes no network requests, downloads no code, contacts no RPC service, and
submits no transaction. Obtain and review dependencies before running it.

Output is JSON. Exit code **0 means a report was produced**, including reports
with `INVALID`, `INDETERMINATE`, or `DENY`; it is not an authorization success.
`--evaluation-time` accepts Unix seconds; otherwise each case uses its fixed
synthetic time. `--max-snapshot-age` defaults to 300 seconds and must be positive.
The current wall clock is not silently substituted for the fixture time.

## Expected results with the pinned companion

The SDK integrity column is the existing single-record `verify_event` result.
It is not an externally anchored batch result or a completeness claim.

| Saved synthetic case | SDK record integrity | Companion evidence integrity | Authorization | Execution match | Delegation state | Illustrative admission |
| --- | --- | --- | --- | --- | --- | --- |
| `approval_mismatch` | VALID | VALID | INVALID | VALID | VALID | DENY |
| `missing_approval` | VALID | VALID | INDETERMINATE | INDETERMINATE | VALID | DENY |
| `stop_with_delegation` | VALID | VALID | VALID | INDETERMINATE | INVALID | DENY |
| `clear_observed` | VALID | VALID | VALID | VALID | VALID | ALLOW |

- **Approval mismatch:** the signed approval commits to a different operation
  digest. Every supplied evidence signature can be valid while the authorization
  comparison proves a mismatch.
- **Missing approval:** available evidence signatures verify, but approval cannot
  be established. An evidence policy may deny admission while the retrospective
  authorization verdict remains unknown.
- **Off-chain stop:** the execution observer reports `offchain_stopped`; the
  chain observer's signed statement still contains an EIP-7702 delegation
  designator. That contradicts the requested clearance. An off-chain stop does
  not establish an on-chain transition.
- **Clear observed:** an independent fixture role signs an observation of empty
  code at the bound block `100`, under a policy accepting `observed_block`
  finality. This supports that scoped historical claim. It does not establish
  current state, global safety, irreversible finality, or inability to delegate
  again. Replaying at a later evaluation time does not renew expired approvals.

`wallet_evidence` retains the canonical companion report, including each
claim's `verdict`, `evidence_refs`, `reasons`, and limitations. `inputs` identifies
the saved record, the hash-covered companion bundle, and the separate trust
inputs. `recorded_event_integrity` retains the actual SDK report, including
per-check results and notes. A local illustrative decision requires both SDK
record integrity `VALID` and the companion's admission result `ALLOW`.
**This decision controls no signer, wallet, deployment controller, or live gate.**

**判定の読み方:** 認可の不一致が証明されたケースと、資料不足で判断できない
ケースを区別します。オフチェーンの停止指示だけでオンチェーン委譲が解除された
ことにはしません。解除の `VALID` は記載されたブロック・観測範囲に限定され、
「現在も安全」「再委譲できない」という意味ではありません。`ALLOW` / `DENY`
はローカルな証跡受付例であり、実システムの送金を許可・拒否する制御ではありません。

## Trust and scope

`trust.json` is a deliberate, out-of-band fixture trust input. The recorder's
public key is separate from the companion's role-specific public keys. The
adapter never derives approval authority or chain-observer trust from a valid
SDK event signature, and never imports trust roots from the event payload.
Distinct fixture keys illustrate distinct roles; they do not prove operational
independence in a deployed system.

The recorder key and every companion signing seed are **public, deterministic
test data**. Signatures authenticate these synthetic statements against the
supplied fixture keys; they do not establish real people, real chain activity,
or truth of the statements. Never use the test seeds to hold assets or operate
a service. Normal replay verifies the stored signatures without resigning,
repairing, or rewriting the records.

`Header.ChainID` is `wallet-demo:audit-stream`, the SDK audit-stream identifier.
The operation's `chain_id` is the separate synthetic Ethereum domain `31337`.
They are not interchangeable. Wallet intent bytes in these fixtures are a
synthetic encoding, not signed Ethereum transactions. The companion experiment
contains separate local EVM tests; this SDK demo does not execute them or claim
public-chain verification. An EIP-7702 transaction's outer receipt alone does
not establish delegation state; see the
[primary EIP-7702 specification](https://eips.ethereum.org/EIPS/eip-7702).

This demo adds no external anchor, event-completeness check, enforcement, or
new SDK result status. Existing SDK trust limits and interpretation notes
continue to apply. A compromised recorder can sign false claims, and a
compromised trusted observer can sign false observations. Independent policy
and execution controls require a separate threat model and implementation.

## Reproducible fixtures and tests

The fixture generator calls the pinned companion's `fixtures.make_fixture`,
then uses the actual SDK producer to seal one `SYS_AUDIT` event per case. Event
time, UUIDv7 randomness, recorder seed, companion seeds, and JSON formatting
are deterministic. The generator writes no expected verification verdicts into
the evidence. Runtime results are recomputed by both verifiers.

`fixtures.json` records the SDK baseline commit, companion source commit, and source hashes;
`companion-lock.json` fixes the companion source bytes. All fixtures and tests
are first-party. This is not evidence of an independent implementation.

```sh
VCP_WALLET_VAP_SPEC=../vap-spec python -m unittest discover -s examples/wallet-authorization-demo -p test_demo.py -v
python examples/wallet-authorization-demo/generate_fixtures.py --vap-spec ../vap-spec --output-dir /tmp/vcp-wallet-fixtures
cmp examples/wallet-authorization-demo/fixtures.json /tmp/vcp-wallet-fixtures/fixtures.json
cmp examples/wallet-authorization-demo/trust.json /tmp/vcp-wallet-fixtures/trust.json
```

Tests cover the four evidence boundaries above, missing companion behavior,
post-signature record tampering, separation of recorder and companion trust,
expired approval evaluation, exact fixture regeneration, source-pin mismatch,
replay without rewriting signatures, and source replacement after the verified
read. The integration suite fails with an
explicit setup error if `VCP_WALLET_VAP_SPEC` is not provided; it does not count
unrun companion checks as passing tests.

The focused `wallet-authorization-demo.yml` workflow runs this integration suite
with Python 3.12, `cryptography==50.0.2`, and a commit-pinned companion checkout.
The existing SDK CI continues to run the core suite independently.

When updating the companion, review its changes, update the source pin, and
regenerate and review the fixtures together. Changing a hash in the lock is
not itself a review, attestation, or approval of the implementation.
