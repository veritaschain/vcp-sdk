import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { replay, MAX_INPUT_BYTES } from '../../tools/replay_explorer_demo.mjs';

const cli = fileURLToPath(new URL('../../tools/replay_explorer_demo.mjs', import.meta.url));
const bundle = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/bundle.json', import.meta.url), 'utf8'));
const trust = JSON.parse(readFileSync(new URL('../../examples/explorer-demo/trust.json', import.meta.url), 'utf8'));
const run = (...args) => spawnSync(process.execPath, [cli, '--json', ...args], { encoding: 'utf8', timeout: 20000 });
function withFile(content, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'vcp-replay-hardening-'));
  try { const file = join(dir, 'input.json'); writeFileSync(file, content); return fn(file); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}
function response(id = 'intact') {
  const c = bundle.cases.find(x => x.id === id);
  const result = replay(c, trust.cases[id]);
  return { format: 'vcp-evidence-demo-verification/1', case_id: id,
    local_status: result.local_status, overall_status: result.overall_status,
    evidence: { events_jsonl: c.events_jsonl, anchor_record_json: c.anchor_record_json, inclusion_proofs: c.inclusion_proofs } };
}
for (const literal of ['null', 'false', '0', '"text"', '[]']) {
  test('file response cannot fall back for ' + literal, () => withFile(literal, path => {
    const r = run('--api-response', path); assert.equal(r.status, 2); assert.equal(r.stdout, '');
  }));
}
test('duplicate outer JSON keys are rejected', () => {
  const text = JSON.stringify(response()).replace('"case_id":"intact"', '"case_id":"tampered","case_id":"intact"');
  withFile(text, path => { const r = run('--api-response', path); assert.equal(r.status, 2); assert.match(r.stderr, /duplicate/i); });
});
test('invalid UTF-8, excessive size and directory inputs are rejected', () => {
  for (const content of [Buffer.from([0xff, 0xfe]), ' '.repeat(MAX_INPUT_BYTES + 1)])
    withFile(content, path => { const r = run('--api-response', path); assert.equal(r.status, 2); assert.equal(r.stdout, ''); });
  assert.equal(run('--api-response', tmpdir()).status, 2);
});
test('all-case mode rejects missing or repeated cases', () => {
  for (const cases of [[bundle.cases[0]], [bundle.cases[0], bundle.cases[0], bundle.cases[2]]])
    withFile(JSON.stringify({ ...bundle, cases }), path => assert.equal(run('--bundle', path).status, 2));
});
test('explicit case supports an unambiguous single-case bundle', () => {
  withFile(JSON.stringify({ ...bundle, cases: [bundle.cases[0]] }), path =>
    assert.equal(run('--bundle', path, '--case', 'intact').status, 0));
});
test('missing proof is indeterminate while malformed duplicate proof is an input error', () => {
  const c = structuredClone(bundle.cases[0]); c.inclusion_proofs.pop();
  const r = replay(c, trust.cases.intact);
  assert.equal(r.local_status, 'INDETERMINATE');
  assert.ok(r.checks.some(x => x.reason === 'MISSING_INCLUSION_PROOF'));
  assert.ok(!r.checks.some(x => x.status === 'INVALID'));
  c.inclusion_proofs.push(c.inclusion_proofs[0]);
  assert.throws(() => replay(c, trust.cases.intact), /Duplicate/);
});
test('outcome equality does not imply fixture identity', () => {
  const r = response('tampered');
  r.evidence.events_jsonl = r.evidence.events_jsonl.replace('999.000', '888.000');
  withFile(JSON.stringify(r), path => {
    const p = run('--api-response', path); assert.equal(p.status, 1, p.stderr);
    const report = JSON.parse(p.stdout).results[0];
    assert.equal(report.matches_expected_outcome, true);
    assert.equal(report.matches_api_claim, true);
    assert.equal(report.fixture_bytes_match, false);
  });
});
test('ordinary response reports explicit source and exact fixture match', () => withFile(JSON.stringify(response()), path => {
  const r = run('--api-response', path); assert.equal(r.status, 0, r.stderr);
  const body = JSON.parse(r.stdout); assert.equal(body.input_source, 'response-file');
  assert.equal(body.results[0].fixture_bytes_match, true);
}));
test('conflicting input modes, repeated args and malformed trust fail closed', () => {
  assert.equal(run('--bundle', 'x', '--api-response', 'y').status, 2);
  assert.equal(run('--case', 'intact', '--case', 'tampered').status, 2);
  withFile('null', path => assert.equal(run('--trust', path).status, 2));
});

test('real HTTP: null, duplicate JSON, non-JSON, oversized bodies and redirects never fall back', async () => {
  const good = JSON.stringify(response()); let redirected = false;
  const server = createServer((req, res) => {
    const cases = {
      '/null': 'null', '/duplicate': '{"x":1,"x":2}',
      '/large': ' '.repeat(MAX_INPUT_BYTES + 1), '/ok': good,
      '/html': good, '/bad-utf8': Buffer.from([0xff]), '/error': 'error code: 1010' + 'x'.repeat(4096)
    };
    if (req.url === '/redirect') { res.writeHead(302, { Location: '/redirected' }); res.end(); return; }
    if (req.url === '/redirected') redirected = true;
    res.writeHead(req.url === '/error' ? 403 : 200, { 'Content-Type': req.url === '/html' ? 'text/html' : 'application/json' });
    res.end(cases[req.url] || good);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    for (const path of ['/null', '/duplicate', '/large', '/html', '/bad-utf8', '/redirect', '/error', '/ok']) {
      const child = spawn(process.execPath, [cli, '--json', '--api-url', 'http://127.0.0.1:' + server.address().port + path]);
      let out = ''; let err = '';
      child.stdout.on('data', b => { out += b; }); child.stderr.on('data', b => { err += b; });
      const [code] = await once(child, 'close');
      assert.equal(code, path === '/ok' ? 0 : 2, path + ': ' + err);
      if (path !== '/ok') assert.equal(out, '', path);
    }
    assert.equal(redirected, false);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
