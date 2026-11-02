import { test } from "node:test";
import assert from "node:assert/strict";
import { MerkleTree, verifyInclusion } from "../dist/index.js";

const leaves = [1, 2, 3].map((value) => new Uint8Array([value]));

test("proof generation rejects non-integer positions before recursion or coercion", () => {
  const tree = new MerkleTree(leaves);
  for (const value of [0.5, 1.5, true, false, "1", null, undefined, NaN, Infinity, 1n, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => tree.inclusionProof(value), {
      name: "RangeError", message: "leaf index must be a safe integer",
    });
    // A stack overflow is also a RangeError: require the explicit input error.
    assert.throws(() => tree.consistencyProof(value), {
      name: "RangeError", message: "first size must be a safe integer",
    });
  }
});

test("proof generation preserves integer range boundaries and valid proofs", () => {
  const tree = new MerkleTree(leaves);
  for (const value of [-1, 3, 4]) {
    assert.throws(() => tree.inclusionProof(value), { name: "RangeError", message: "leaf index out of range" });
  }
  for (const value of [-1, 4]) {
    assert.throws(() => tree.consistencyProof(value), { name: "RangeError", message: "first size out of range" });
  }
  assert.deepEqual(tree.consistencyProof(0), []);
  assert.deepEqual(tree.consistencyProof(tree.size), []);
  for (let i = 0; i < leaves.length; i++) {
    assert.ok(verifyInclusion(leaves[i], i, leaves.length, tree.inclusionProof(i), tree.root));
  }
  const empty = new MerkleTree([]);
  assert.deepEqual(empty.consistencyProof(0), []);
  assert.throws(() => empty.inclusionProof(0), { name: "RangeError", message: "leaf index out of range" });
});
