import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  canonicalizeString, parseJson, computeEventHash, merkleRoot, fromHex, toHex,
  SigningKey, VerifyKey, signEventHash, signMerkleRoot,
  verifyEventSignature, verifyRootSignature, verifyBatch,
} from "../dist/index.js";

const path = fileURLToPath(new URL("../../test-vectors/interoperability-boundaries.json", import.meta.url));
const fixtures = JSON.parse(readFileSync(path, "utf8"));
const { cases, anchorFixture: anchor, testKey } = fixtures;

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

for (const c of cases.filter(x => x.kind === "signature-bytes")) {
  test("signature input bytes: " + c.id, () => {
    const eventBytes = fromHex(c.expectedEventSignedBytesHex);
    const rootBytes = fromHex(c.expectedRootSignedBytesHex);
    assert.deepEqual(Buffer.from(eventBytes), Buffer.from(c.digestHex, "ascii"));
    assert.equal(toHex(rootBytes), c.digestHex);
    assert.notDeepEqual(eventBytes, rootBytes);

    const key = new SigningKey(testKey.seedHex);
    const publicKey = new VerifyKey(testKey.publicKeyHex);
    assert.equal(toHex(key.verifyKey.raw), testKey.publicKeyHex);
    // Frozen signatures were calculated outside the SDK. These tests are first-party.
    assert.equal(Buffer.from(key.sign(eventBytes)).toString("base64"), c.expectedEventSignatureBase64);
    assert.equal(Buffer.from(key.sign(rootBytes)).toString("base64"), c.expectedRootSignatureBase64);
    assert.equal(signEventHash(c.digestHex, key), c.expectedEventSignatureBase64);
    assert.equal(signMerkleRoot(c.digestHex, key), c.expectedRootSignatureBase64);
    assert.equal(verifyEventSignature(c.digestHex, c.expectedEventSignatureBase64, publicKey), c.expectedEventVerification);
    assert.equal(verifyRootSignature(c.digestHex, c.expectedRootSignatureBase64, publicKey), c.expectedRootVerification);
    assert.equal(verifyEventSignature(c.digestHex, c.expectedRootSignatureBase64, publicKey), c.expectedCrossVerification);
    assert.equal(verifyRootSignature(c.digestHex, c.expectedEventSignatureBase64, publicKey), c.expectedCrossVerification);
  });
}

test("anchor fixture literal bytes", () => {
  assert.equal(canonicalizeString(anchor.event.Header), anchor.expectedHeaderCanonical);
  assert.equal(canonicalizeString(anchor.event.Payload), anchor.expectedPayloadCanonical);
  const literalBytes = Buffer.from(anchor.expectedHeaderCanonical + anchor.expectedPayloadCanonical, "utf8");
  assert.equal(createHash("sha256").update(literalBytes).digest("hex"), anchor.expectedEventHashHex);
  assert.equal(computeEventHash(anchor.event.Header, anchor.event.Payload), anchor.expectedEventHashHex);
  const leaf = fromHex(anchor.expectedEventHashHex);
  assert.equal(createHash("sha256").update(Buffer.concat([Buffer.from([0]), leaf])).digest("hex"), anchor.expectedRootHex);
  assert.equal(toHex(merkleRoot([leaf])), anchor.expectedRootHex);
});

for (const c of cases.filter(x => x.kind === "anchor-record")) {
  test("anchor record: " + c.id, () => {
    const record = { ...structuredClone(anchor.record), ...structuredClone(c.anchorPatch) };
    // Metadata/proof changes retain the same root and root-only signature.
    assert.equal(record.MerkleRoot, anchor.record.MerkleRoot);
    assert.equal(record.Signature, anchor.record.Signature);
    const report = verifyBatch([structuredClone(anchor.event)], record, {
      publicKey: testKey.publicKeyHex, anchorPublicKey: testKey.publicKeyHex,
    });
    const expected = { ...anchor.expectedChecks, ...c.expectedCheckOverrides };
    const actual = {};
    for (const check of report.checks) {
      assert.equal(Object.hasOwn(actual, check.name), false, "single-event fixture should have one check of each kind");
      actual[check.name] = { status: check.status };
      if (check.reason != null) actual[check.name].reason = check.reason;
    }
    assert.deepEqual(actual, expected);
    // A proven mismatch stays INVALID despite missing external evidence.
    assert.equal(report.status, c.expectedStatus);
    assert.ok(report.notes.some(note => note.includes("signature covers the Merkle root only")));
    assert.match(report.checks.find(check => check.name === "anchor_timestamp_format").detail, /not covered by the signature/);
  });
}
