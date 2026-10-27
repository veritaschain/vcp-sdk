import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalizeString, parseJson, merkleRoot, fromHex, toHex } from "../dist/index.js";

const path = fileURLToPath(new URL("../../test-vectors/interoperability-boundaries.json", import.meta.url));
const cases = JSON.parse(readFileSync(path, "utf8")).cases;
for (const c of cases.filter(x => x.kind === "canonical-json")) {
  test("canonical bytes: " + c.id, () => {
    const actual = canonicalizeString(parseJson(c.input));
    assert.deepEqual(Buffer.from(actual, "utf8"), Buffer.from(c.expectedCanonical, "utf8"));
  });
}
for (const c of cases.filter(x => x.kind === "merkle-root")) {
  test("Merkle root: " + c.id, () => {
    assert.equal(toHex(merkleRoot(c.leafHex.map(fromHex))), c.expectedRootHex);
  });
}
test("three leaves and four leaves have different roots", () => {
  const roots = cases.filter(x => x.kind === "merkle-root").map(x => x.expectedRootHex);
  assert.equal(roots.length, 2);
  assert.notEqual(roots[0], roots[1]);
});
