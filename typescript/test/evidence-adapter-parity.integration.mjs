/** Actual pinned API source + actual SDK, no HTTP mocks. First-party parity only. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import * as sdk from '../dist/index.js';
import { replay } from '../../tools/replay_explorer_demo.mjs';
assert.ok(process.env.VCP_EVIDENCE_API_CORE, 'Use the reviewed API core path');
const source = readFileSync(process.env.VCP_EVIDENCE_API_CORE, 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { createEvidenceDemo } = await import('data:text/javascript;base64,' + Buffer.from(compiled.outputText).toString('base64'));
const bundle = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/bundle.json', import.meta.url), 'utf8'));
const trust = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/trust.json', import.meta.url), 'utf8'));
function compare(bundle, trust) {
  const api = createEvidenceDemo(sdk, JSON.stringify(bundle), JSON.stringify(trust));
  for (const c of bundle.cases) {
    const local = replay(c, trust.cases[c.id]); const remote = api.verify(c.id);
    assert.deepEqual([local.local_status, local.overall_status], [remote.local_status, remote.overall_status], c.id);
    assert.deepEqual(local.checks, remote.checks, 'per-check result/reason/scope/subject: ' + c.id);
    assert.deepEqual(local.notes, remote.notes, 'notes: ' + c.id);
  }
}
test('all three fixed cases have full API/CLI parity', () => compare(bundle, trust));
test('missing proof has the same indeterminate check', () => {
  const b = structuredClone(bundle); b.cases[0].inclusion_proofs.pop(); compare(b, trust);
});
test('wrong proof binding has the same invalid reason', () => {
  const b = structuredClone(bundle); b.cases[0].inclusion_proofs[0].merkle_root = 'ab'.repeat(32); compare(b, trust);
});
test('extra proof for absent event is invalid in both', () => {
  const b = structuredClone(bundle); const p = structuredClone(b.cases[0].inclusion_proofs[0]);
  p.event_id = '00000000-0000-4000-8000-000000000000'; b.cases[0].inclusion_proofs.push(p); compare(b, trust);
});
test('post-signing payload mutation has the same checks', () => {
  const b = structuredClone(bundle); b.cases[0].events_jsonl = b.cases[0].events_jsonl.replace('151.230', '777.000'); compare(b, trust);
});
test('explicit removal of trust has the same indeterminate reasons', () => {
  const t = structuredClone(trust); t.cases.intact = { actor_public_keys: {}, anchor_public_key: null }; compare(bundle, t);
});
test('duplicate proof is a rejected input in both adapters', () => {
  const b = structuredClone(bundle); b.cases[0].inclusion_proofs.push(b.cases[0].inclusion_proofs[0]);
  assert.throws(() => createEvidenceDemo(sdk, JSON.stringify(b), JSON.stringify(trust)), /duplicate/i);
  assert.throws(() => replay(b.cases[0], trust.cases.intact), /duplicate/i);
});
