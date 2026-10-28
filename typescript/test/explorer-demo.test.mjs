import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  parseJson, parseJsonLines, verifyBatch, verifyChain, verifyInclusionProof,
  computeEventHash, combine,
} from "../dist/index.js";

const bundle = JSON.parse(readFileSync(new URL("../../examples/explorer-demo/bundle.json", import.meta.url), "utf8"));
const trust = JSON.parse(readFileSync(new URL("../../examples/explorer-demo/trust.json", import.meta.url), "utf8"));
const cases = new Map(bundle.cases.map(c => [c.id, c]));

// Hand-written test expectations; the API must compute its reports afresh.
const expected = {
  intact: ["VALID", "INDETERMINATE"],
  tampered: ["INVALID", "INVALID"],
  "missing-key": ["INDETERMINATE", "INDETERMINATE"],
};

for (const [id, outcomes] of Object.entries(expected)) {
  test(`Python-produced evidence, TypeScript verification: ${id}`, () => {
    const c = cases.get(id);
    const policy = trust.cases[id];
    const events = parseJsonLines(c.events_jsonl);
    const record = parseJson(c.anchor_record_json);
    const report = verifyBatch(events, record, {
      publicKey: policy.actor_public_keys,
      anchorPublicKey: policy.anchor_public_key,
      requireSignAlgo: "ED25519",
    });
    const chain = verifyChain(events);
    const local = combine([
      ...report.checks.filter(c => c.name !== "external_anchor").map(c => c.status),
      ...chain.checks.map(c => c.status),
    ]);
    assert.deepEqual([local, report.status], outcomes);
    const external = report.checks.filter(c => c.name === "external_anchor");
    assert.equal(external.length, 1);
    assert.equal(external[0].status, "INDETERMINATE");
    assert.equal(external[0].reason, "MISSING_ANCHOR_PROOF");
    assert.equal(Object.hasOwn(record, "AnchorTarget"), false);
    if (id === "tampered") {
      assert.ok(report.checks.some(c => c.reason === "HASH_MISMATCH"));
      assert.ok(report.checks.some(c => c.reason === "SIGNATURE_MISMATCH"));
    }
    if (id === "missing-key") {
      assert.ok(report.checks.some(c => c.name === "signature" && c.reason === "KEY_NOT_ESTABLISHED"));
      assert.ok(report.checks.some(c => c.name === "root_signature" && c.reason === "KEY_NOT_ESTABLISHED"));
    }
  });

  test(`Proofs bind to recomputed payload hash: ${id}`, () => {
    const c = cases.get(id);
    const events = parseJsonLines(c.events_jsonl);
    assert.equal(events.length, c.inclusion_proofs.length);
    for (const proof of c.inclusion_proofs) {
      const event = events[proof.index];
      assert.equal(event.Header.EventID, proof.event_id);
      assert.equal(event.Security.EventHash, proof.event_hash);
      const digest = computeEventHash(event.Header, event.Payload, {
        prevHash: event.Security.PrevHash,
        algo: event.Security.HashAlgo,
      });
      const report = verifyInclusionProof(digest, proof.index, proof.tree_size, proof.proof, proof.merkle_root);
      const wanted = id === "tampered" && proof.index === 2 ? "INVALID" : "VALID";
      assert.equal(report.checks.find(c => c.name === "inclusion").status, wanted);
      assert.equal(report.checks.find(c => c.name === "root_authenticity").status, "INDETERMINATE");
    }
  });
}

test("normal JSON transport preserves exact inner evidence and nanosecond integers", () => {
  const transported = JSON.parse(JSON.stringify(bundle));
  assert.deepEqual(transported, bundle);
  const intact = cases.get("intact");
  const missing = cases.get("missing-key");
  assert.equal(intact.events_jsonl, missing.events_jsonl);
  assert.equal(intact.anchor_record_json, missing.anchor_record_json);
  const events = parseJsonLines(intact.events_jsonl);
  assert.equal(typeof events[0].Header.TimestampInt, "bigint");
  assert.equal(events[0].Header.TimestampInt, 1793145600123456789n);
  const rounded = JSON.parse(intact.events_jsonl.split("\n")[0]).Header.TimestampInt;
  assert.notEqual(BigInt(rounded), events[0].Header.TimestampInt);
  assert.deepEqual(trust.cases["missing-key"], { actor_public_keys: {}, anchor_public_key: null });
  for (const c of bundle.cases) {
    assert.deepEqual(Object.keys(c).sort(), ["anchor_record_json", "description", "events_jsonl", "id", "inclusion_proofs", "title"]);
  }
});
