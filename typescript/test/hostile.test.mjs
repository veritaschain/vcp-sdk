// test-vectors/hostile.json: malformed and adversarial inputs with hand-written expectations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as vcp from "../dist/index.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const H = vcp.parseJson(readFileSync(here + "../../test-vectors/hostile.json", "utf8"));

function run(c) {
  if (c.kind === "event") return vcp.verifyEvent(c.event, c.public_key, c.require_sign_algo);
  if (c.kind === "batch") {
    const ext = c.external_anchor_result;
    return vcp.verifyBatch(c.events, c.anchor_record, {
      publicKey: c.public_key,
      externalAnchorVerifier: ext === null ? null : () => ext,
      requireSignAlgo: c.require_sign_algo ?? null,
    });
  }
  if (c.kind === "chain") return vcp.verifyChain(c.events, c.prior_hash);
  return vcp.verifyInclusionProof(...c.args);
}

for (const c of H.cases) {
  test(c.name, () => {
    if (["event", "batch", "chain", "inclusion"].includes(c.kind)) {
      const rep = run(c);
      const reasons = new Set(rep.checks.filter((x) => x.status !== "VALID").map((x) => x.reason));
      assert.ok(!reasons.has("VERIFIER_ERROR"), JSON.stringify(rep.checks));
      assert.equal(rep.status, c.expected, vcp.toJson(rep.checks));
      if (c.reason) assert.ok(reasons.has(c.reason), vcp.toJson(rep.checks));
      // same checks, same order, as the Python verifier
      assert.deepEqual(rep.checks.map((x) => [x.name, x.status, x.reason ?? "", x.subject ?? ""]), c.python_checks);
    } else if (c.kind === "parse") {
      if (!c.ok) assert.throws(() => vcp.parseJson(c.text), vcp.StrictJSONError);
      else {
        const v = vcp.parseJson(c.text);
        if (c.canonical === null) assert.throws(() => vcp.canonicalizeString(v), vcp.CanonicalizationError);
        else assert.equal(vcp.canonicalizeString(v), c.canonical);
      }
    } else if (c.kind === "jsonl") {
      if (c.count === null) assert.throws(() => vcp.parseJsonLines(c.text), vcp.StrictJSONError);
      else assert.equal(vcp.parseJsonLines(c.text).length, c.count);
    }
  });
}

test("external verifier that throws", () => {
  const key = new vcp.SigningKey("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const p = new vcp.Producer(key, "a", "c", "org.example:p");
  p.create("INIT", { "VCP-GOV": { AlgoID: "x" } }, { timestampNs: 1791504000000000000n });
  const { batch, record } = p.closeBatch({ anchorTarget: { Type: "TSA", Identifier: "t", Proof: "p" } });
  const rep = vcp.verifyBatch(batch.events, record, { publicKey: key.verifyKey, externalAnchorVerifier: () => { throw new Error("network down"); } });
  assert.equal(rep.status, vcp.INDETERMINATE);
  assert.ok(rep.notes.some((n) => n.includes("network down")));
});
