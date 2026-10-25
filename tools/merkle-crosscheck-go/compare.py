#!/usr/bin/env python3
"""Compare the Go (transparency-dev/merkle) output with veritaschain_vcp.merkle."""
import hashlib
import json
import sys

from veritaschain_vcp import merkle

bad = rows = 0
for line in open(sys.argv[1]):
    r = json.loads(line)
    n = r["n"]
    rows += 1
    ls = [hashlib.sha256(str(i).encode()).digest() for i in range(n)]
    t = merkle.MerkleTree(ls)
    bad += t.root.hex() != r["root"]
    bad += sum([x.hex() for x in t.inclusion_proof(int(i))] != p for i, p in r["inclusion"].items())
    bad += sum([x.hex() for x in t.consistency_proof(int(m))] != p for m, p in r["consistency"].items())
print(f"{rows} tree sizes compared, {bad} mismatches")
sys.exit(1 if bad or rows == 0 else 0)
