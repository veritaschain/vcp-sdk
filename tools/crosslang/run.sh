#!/usr/bin/env bash
# Cross-language check: events produced by one SDK verify with the other.
# Needs the Python package installed (pip install -e python) and the TypeScript build (npm run build).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
seed=4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
pub=$(python -c "import veritaschain_vcp as v; print(v.SigningKey('$seed').verify_key.to_base64())")

# TypeScript -> Python
node "$here/ts_produce.mjs" "$tmp" "$seed"
python - "$tmp" "$pub" <<'EOF'
import sys, json
import veritaschain_vcp as v
from veritaschain_vcp.jsonio import load_jsonl, loads
d, pub = sys.argv[1], sys.argv[2]
events = load_jsonl(open(f"{d}/ts-events.jsonl", "rb").read())
record = loads(open(f"{d}/ts-anchor.json", "rb").read())
r = v.verify_batch(events, record, pub, external_anchor_verifier=lambda r: True)
c = v.verify_chain(events)
print("TS -> Python:", r.status, c.status)
assert r.status == v.VALID and c.status == v.VALID, json.dumps(r.to_dict(), indent=1)
EOF

# Python -> TypeScript
python - "$tmp" "$seed" <<'EOF'
import sys, json
import veritaschain_vcp as v
d, seed = sys.argv[1], sys.argv[2]
k = v.SigningKey(seed)
p = v.Producer(k, "py-producer", "chain-y", "org.veritaschain.sdk:crosslang", precision="NANOSECOND", use_prev_hash=True)
for i in range(11):
    p.create("ORD" if i else "INIT", {"VCP-RISK": {"Limit": f"{i}.5", "Note": "混在 \u2028 \u001f"}}, timestamp_ns=1791504000123456768 + i * 256_000)
b, rec = p.close_batch(anchor_target={"Type": "TSA", "Identifier": "tsa.example", "Proof": "synthetic"}, timestamp_ns=1791505000000000000)
open(f"{d}/py-events.jsonl", "w", encoding="utf-8").write("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in b.events))
open(f"{d}/py-anchor.json", "w", encoding="utf-8").write(json.dumps(rec))
EOF
printf 'Python -> TS: '
node "$here/ts_verify.mjs" "$tmp/py-events.jsonl" "$tmp/py-anchor.json" "$pub" VALID
echo "cross-language check passed"
