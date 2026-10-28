import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../../tools/replay_explorer_demo.mjs', import.meta.url));
const bundle = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/bundle.json', import.meta.url), 'utf8'));
const run = (...args) => spawnSync(process.execPath, [cli, '--json', ...args], { encoding: 'utf8' });

test('offline replay computes all three expected outcomes', () => {
  const r = run();
  assert.equal(r.status, 0, r.stderr);
  const body = JSON.parse(r.stdout);
  assert.equal(body.success, true);
  assert.equal(body.first_party, true);
  assert.equal(body.external_anchor_verified, false);
  assert.deepEqual(body.results.map(x => [x.id, x.local_status, x.overall_status]), [
    ['intact', 'VALID', 'INDETERMINATE'],
    ['tampered', 'INVALID', 'INVALID'],
    ['missing-key', 'INDETERMINATE', 'INDETERMINATE']
  ]);
  assert.ok(body.results.every(x => x.matches_fixed_demo));
  assert.ok(body.results[0].checks.some(x => x.name === 'external_anchor' &&
    x.status === 'INDETERMINATE'));
});

test('offline replay rejects a fabricated API success claim', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vcp-demo-response-'));
  try {
    const c = bundle.cases.find(x => x.id === 'tampered');
    const file = join(dir, 'response.json');
    const api = {
      format: 'vcp-evidence-demo-verification/1',
      case_id: 'tampered', local_status: 'VALID', overall_status: 'VALID',
      evidence: {
        events_jsonl: c.events_jsonl,
        anchor_record_json: c.anchor_record_json,
        inclusion_proofs: c.inclusion_proofs
      }
    };
    writeFileSync(file, JSON.stringify(api));
    const mismatch = run('--api-response', file);
    assert.equal(mismatch.status, 1, mismatch.stderr);
    assert.equal(JSON.parse(mismatch.stdout).results[0].matches_api_claim, false);
    api.local_status = 'INVALID';
    api.overall_status = 'INVALID';
    writeFileSync(file, JSON.stringify(api));
    const matching = run('--api-response', file);
    assert.equal(matching.status, 0, matching.stderr);
    assert.equal(JSON.parse(matching.stdout).results[0].matches_api_claim, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('altering an intact event invalidates the offline replay expectation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vcp-demo-altered-'));
  try {
    const edited = structuredClone(bundle);
    const intact = edited.cases.find(x => x.id === 'intact');
    const original = intact.events_jsonl;
    intact.events_jsonl = original.replace('151.230', '999.999');
    assert.notEqual(intact.events_jsonl, original);
    const file = join(dir, 'bundle.json');
    writeFileSync(file, JSON.stringify(edited));
    const r = run('--bundle', file, '--case', 'intact');
    assert.equal(r.status, 1, r.stderr);
    const x = JSON.parse(r.stdout).results[0];
    assert.equal(x.local_status, 'INVALID');
    assert.equal(x.matches_fixed_demo, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('help and malformed inputs are explicit', () => {
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /Usage/);
  const unknown = run('--case', 'not-a-case');
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /Unrecognized demo case/);
});

test('duplicate detached proof cannot be ignored by local replay', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vcp-demo-duplicate-proof-'));
  try {
    const edited = structuredClone(bundle);
    const c = edited.cases.find(x => x.id === 'intact');
    c.inclusion_proofs.push(structuredClone(c.inclusion_proofs[0]));
    const file = join(dir, 'bundle.json');
    writeFileSync(file, JSON.stringify(edited));
    const r = run('--bundle', file, '--case', 'intact');
    assert.equal(r.status, 1, r.stderr);
    const report = JSON.parse(r.stdout).results[0];
    assert.equal(report.matches_fixed_demo, false);
    assert.ok(report.checks.some(x => x.reason === 'PROOF_SET_MISMATCH' && x.status === 'INVALID'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
