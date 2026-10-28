import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const cli = fileURLToPath(new URL('../../tools/replay_explorer_demo.mjs', import.meta.url));
const bundle = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/bundle.json', import.meta.url), 'utf8'));
const run = (...args) => spawnSync(process.execPath, [cli, '--json', ...args], { encoding: 'utf8', timeout: 20000 });
function temporary(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'vcp-demo-'));
  try { return fn(join(dir, 'input.json')); } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('offline replay computes all three expected outcomes', () => {
  const r = run(); assert.equal(r.status, 0, r.stderr);
  const body = JSON.parse(r.stdout);
  assert.equal(body.success, true); assert.equal(body.first_party, true); assert.equal(body.external_anchor_verified, false);
  assert.deepEqual(body.results.map(x => [x.id, x.local_status, x.overall_status]), [
    ['intact', 'VALID', 'INDETERMINATE'], ['tampered', 'INVALID', 'INVALID'],
    ['missing-key', 'INDETERMINATE', 'INDETERMINATE']]);
  assert.ok(body.results.every(x => x.matches_expected_outcome && x.fixture_bytes_match));
  assert.ok(body.results[0].checks.some(x => x.name === 'external_anchor' && x.status === 'INDETERMINATE'));
});
test('offline replay rejects a fabricated API success claim', () => temporary(file => {
  const c = bundle.cases.find(x => x.id === 'tampered');
  const api = { format: 'vcp-evidence-demo-verification/1', case_id: 'tampered',
    local_status: 'VALID', overall_status: 'VALID', evidence: {
      events_jsonl: c.events_jsonl, anchor_record_json: c.anchor_record_json, inclusion_proofs: c.inclusion_proofs } };
  writeFileSync(file, JSON.stringify(api));
  const mismatch = run('--api-response', file); assert.equal(mismatch.status, 1, mismatch.stderr);
  assert.equal(JSON.parse(mismatch.stdout).results[0].matches_api_claim, false);
  api.local_status = 'INVALID'; api.overall_status = 'INVALID'; writeFileSync(file, JSON.stringify(api));
  const matching = run('--api-response', file); assert.equal(matching.status, 0, matching.stderr);
  assert.equal(JSON.parse(matching.stdout).results[0].matches_api_claim, true);
}));
test('altering an intact event invalidates the offline replay expectation', () => temporary(file => {
  const edited = structuredClone(bundle); const c = edited.cases.find(x => x.id === 'intact');
  const original = c.events_jsonl; c.events_jsonl = original.replace('151.230', '999.999');
  assert.notEqual(c.events_jsonl, original); writeFileSync(file, JSON.stringify(edited));
  const r = run('--bundle', file, '--case', 'intact'); assert.equal(r.status, 1, r.stderr);
  assert.equal(JSON.parse(r.stdout).results[0].local_status, 'INVALID');
}));
test('help and malformed inputs are explicit', () => {
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /Usage/);
  const r = run('--case', 'not-a-case'); assert.equal(r.status, 2); assert.match(r.stderr, /Unrecognized demo case/);
});
test('duplicate detached proof is rejected like API configuration', () => temporary(file => {
  const edited = structuredClone(bundle); const c = edited.cases[0];
  c.inclusion_proofs.push(structuredClone(c.inclusion_proofs[0])); writeFileSync(file, JSON.stringify(edited));
  const r = run('--bundle', file, '--case', 'intact');
  assert.equal(r.status, 2, r.stderr); assert.equal(r.stdout, ''); assert.match(r.stderr, /Duplicate proof/);
}));
test('HTTP probe identifies its application without a forged browser Origin', async () => {
  const c = bundle.cases[0]; const api = { format: 'vcp-evidence-demo-verification/1', case_id: 'intact',
    local_status: 'VALID', overall_status: 'INDETERMINATE', evidence: {
      events_jsonl: c.events_jsonl, anchor_record_json: c.anchor_record_json, inclusion_proofs: c.inclusion_proofs } };
  let agent; let origin;
  const server = createServer((req, res) => { agent = req.headers['user-agent']; origin = req.headers.origin;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(api)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const child = spawn(process.execPath, [cli, '--api-url', 'http://127.0.0.1:' + server.address().port + '/verification', '--json']);
    let output = ''; let errors = '';
    child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { errors += b; });
    const [code] = await once(child, 'close'); assert.equal(code, 0, errors);
    assert.match(agent, /^VCP-Evidence-Replay\/0\.1 /); assert.equal(origin, undefined);
    assert.equal(JSON.parse(output).results[0].matches_api_claim, true);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
