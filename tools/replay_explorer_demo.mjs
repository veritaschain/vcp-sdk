#!/usr/bin/env node
/** First-party fixed-fixture replay. Never falls back from an invalid response. */
import { openSync, closeSync, fstatSync, readSync, constants } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import {
  VERSION, VCP_SPEC_VERSION, VCP_SPEC_COMMIT, parseJson, parseJsonLines, parseHash,
  verifyBatch, verifyChain, verifyInclusionProof, computeEventHash, combine,
  publicKeyProblem, fromHex
} from '../typescript/dist/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_TRUST_BYTES = 64 * 1024;
const expected = Object.freeze({
  intact: ['VALID', 'INDETERMINATE'], tampered: ['INVALID', 'INVALID'],
  'missing-key': ['INDETERMINATE', 'INDETERMINATE']
});
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonblank = x => typeof x === 'string' && x.length > 0;
const equalHash = (a, b) => { try { return parseHash(a) === parseHash(b); } catch { return false; } };
const equalInt = (value, n) =>
  (typeof value === 'bigint' || (typeof value === 'number' && Number.isSafeInteger(value))) &&
  BigInt(value) === BigInt(n);
const decode = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);

/** Read regular files only; bound bytes even if the file grows during reading. */
function read(path, limit = MAX_INPUT_BYTES) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw Error('Input must be a regular file within the byte limit');
    const data = Buffer.alloc(limit + 1);
    let count = 0;
    while (count < data.length) {
      const n = readSync(fd, data, count, data.length - count, null);
      if (n === 0) break;
      count += n;
    }
    if (count > limit) throw Error('Input exceeds byte limit');
    return parseJson(decode(data.subarray(0, count)));
  } finally { closeSync(fd); }
}

async function responseText(response, limit, prefixOnly = false) {
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > limit) {
        if (!prefixOnly) throw Error('HTTP response exceeds byte limit');
        chunks.push(value.subarray(0, limit - size));
        size = limit;
        break;
      }
      chunks.push(value); size += value.byteLength;
    }
    const bytes = Buffer.concat(chunks, size);
    return prefixOnly ? bytes.toString('utf8') : decode(bytes);
  } finally { await reader.cancel().catch(() => {}); }
}

function options(argv) {
  const o = { bundle: resolve(root, 'examples/explorer-demo/bundle.json'),
    trust: resolve(root, 'examples/explorer-demo/trust.json'),
    mode: 'bundle', responseFile: null, apiUrl: null, caseId: null, json: false };
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (seen.has(arg)) throw Error('Repeated argument: ' + arg);
    seen.add(arg);
    if (arg === '--json') o.json = true;
    else if (arg === '--help') {
      process.stdout.write('Usage: node tools/replay_explorer_demo.mjs [--case intact|tampered|missing-key] [--bundle path | --api-response path | --api-url URL] [--trust path] [--json]\nBuild first: npm --prefix typescript ci && npm --prefix typescript run build\n');
      return null;
    } else if (['--bundle', '--trust', '--api-response', '--api-url', '--case'].includes(arg)) {
      if (++i >= argv.length || !argv[i] || argv[i].startsWith('--')) throw Error('Missing value for ' + arg);
      if (arg === '--bundle') o.bundle = resolve(argv[i]);
      if (arg === '--trust') o.trust = resolve(argv[i]);
      if (arg === '--api-response') { o.responseFile = resolve(argv[i]); o.mode = 'response-file'; }
      if (arg === '--api-url') { o.apiUrl = argv[i]; o.mode = 'response-http'; }
      if (arg === '--case') o.caseId = argv[i];
    } else throw Error('Unknown argument: ' + arg);
  }
  if (['--bundle', '--api-response', '--api-url'].filter(x => seen.has(x)).length > 1)
    throw Error('Choose only one evidence input source');
  if (o.caseId && !Object.hasOwn(expected, o.caseId)) throw Error('Unrecognized demo case');
  return o;
}

function validatePolicy(policy) {
  if (!object(policy) || !object(policy.actor_public_keys) ||
      !Object.hasOwn(policy, 'anchor_public_key') || Object.keys(policy.actor_public_keys).length > 100)
    throw Error('Explicit actor/root trust configuration required');
  for (const key of [...Object.values(policy.actor_public_keys), policy.anchor_public_key]) {
    if (key === null && key === policy.anchor_public_key) continue;
    if (typeof key !== 'string' || !/^[0-9a-f]{64}$/i.test(key) || publicKeyProblem(fromHex(key)) !== null)
      throw Error('Malformed Ed25519 trust key');
  }
  if (Object.values(policy.actor_public_keys).some(key => key === null)) throw Error('Null actor key');
}

function validateEvidence(c) {
  if (!object(c) || !nonblank(c.events_jsonl) || !nonblank(c.anchor_record_json) ||
      !Array.isArray(c.inclusion_proofs) || c.inclusion_proofs.length > 100 ||
      Buffer.byteLength(c.events_jsonl) > 512 * 1024 || Buffer.byteLength(c.anchor_record_json) > 64 * 1024)
    throw Error('Bounded evidence strings and proof array required');
  const ids = new Set();
  for (const p of c.inclusion_proofs) {
    if (!object(p) || !nonblank(p.event_id) || p.event_id.length > 128 ||
        !Number.isSafeInteger(p.index) || p.index < 0 ||
        !Number.isSafeInteger(p.tree_size) || p.tree_size <= p.index ||
        typeof p.event_hash !== 'string' || !/^(?:sha256:)?[0-9a-f]{64}$/i.test(p.event_hash) ||
        typeof p.merkle_root !== 'string' || !/^[0-9a-f]{64}$/i.test(p.merkle_root) ||
        !Array.isArray(p.proof) || p.proof.length > 53 ||
        p.proof.some(h => typeof h !== 'string' || !/^[0-9a-f]{64}$/i.test(h)))
      throw Error('Malformed inclusion proof');
    if (ids.has(p.event_id)) throw Error('Duplicate proof event_ids');
    ids.add(p.event_id);
  }
  const events = parseJsonLines(c.events_jsonl);
  const record = parseJson(c.anchor_record_json);
  if (!events.length || events.length > 100 || !object(record)) throw Error('Malformed or oversized event batch');
  const eventIds = new Set();
  for (const e of events) {
    if (!object(e) || !object(e.Header) || !object(e.Payload) || !object(e.Security) ||
        !nonblank(e.Header.EventID) || eventIds.has(e.Header.EventID))
      throw Error('Malformed event or duplicate EventID');
    eventIds.add(e.Header.EventID);
  }
  return { events, record };
}

/** Same covered checks as the portable API. Missing proof != proven mismatch. */
export function replay(c, policy) {
  validatePolicy(policy);
  const { events, record } = validateEvidence(c);
  const checks = []; const notes = [];
  function append(group, report, subject) {
    for (const x of report.checks) checks.push({ ...x, ...(subject ? { subject } : {}), group,
      scope: x.name === 'external_anchor' || x.name === 'root_authenticity' ? 'external' : 'local' });
    notes.push(...report.notes);
  }
  append('batch', verifyBatch(events, record, { publicKey: policy.actor_public_keys,
    anchorPublicKey: policy.anchor_public_key, requireSignAlgo: 'ED25519' }));
  append('chain', verifyChain(events));
  for (const [index, event] of events.entries()) {
    const s = event.Security; const id = event.Header.EventID;
    const p = c.inclusion_proofs.find(item => item.event_id === id);
    if (!p) {
      checks.push({ name: 'inclusion', status: 'INDETERMINATE', reason: 'MISSING_INCLUSION_PROOF',
        group: 'inclusion', scope: 'local', subject: id });
      continue;
    }
    const bound = p.index === index && p.tree_size === events.length &&
      equalInt(record.EventCount, p.tree_size) && equalInt(s.MerkleIndex, index) &&
      equalHash(p.event_hash, s.EventHash) && equalHash(p.merkle_root, s.MerkleRoot) &&
      equalHash(p.merkle_root, record.MerkleRoot);
    checks.push({ name: 'proof_binding', status: bound ? 'VALID' : 'INVALID',
      ...(bound ? {} : { reason: 'PROOF_BINDING_MISMATCH',
        detail: 'Proof event hash, index, size or root differs from the supplied event/batch record.' }),
      group: 'inclusion', scope: 'local', subject: id });
    try {
      const hash = computeEventHash(event.Header, event.Payload, { prevHash: s.PrevHash, algo: s.HashAlgo });
      append('inclusion', verifyInclusionProof(hash, p.index, p.tree_size, p.proof, p.merkle_root, false), id);
    } catch {
      checks.push({ name: 'inclusion', status: 'INDETERMINATE', reason: 'HASH_NOT_RECOMPUTED',
        detail: 'The event hash could not be recomputed; no inclusion success is asserted.',
        group: 'inclusion', scope: 'local', subject: id });
    }
  }
  for (const p of c.inclusion_proofs) if (!events.some(e => e.Header.EventID === p.event_id))
    checks.push({ name: 'proof_binding', status: 'INVALID', reason: 'EVENT_NOT_IN_BATCH',
      group: 'inclusion', scope: 'local', subject: p.event_id });
  return { id: c.id,
    local_status: combine(checks.filter(x => x.scope === 'local').map(x => x.status)),
    overall_status: combine(checks.map(x => x.status)), checks, notes: [...new Set(notes)] };
}

function bundleCases(bundle, selected) {
  if (!object(bundle) || bundle.format !== 'vcp-evidence-demo/1' ||
      bundle.sdk_version !== VERSION || bundle.spec_version !== VCP_SPEC_VERSION ||
      !Array.isArray(bundle.cases) || !bundle.cases.length || bundle.cases.length > 3)
    throw Error('Unsupported fixed demo bundle');
  const ids = bundle.cases.map(c => c?.id);
  if (ids.some(id => typeof id !== 'string' || !Object.hasOwn(expected, id)) ||
      new Set(ids).size !== ids.length || (!selected && ids.length !== 3))
    throw Error('All-case mode requires exactly three unique known cases; subsets require --case');
  const cases = bundle.cases.filter(c => !selected || c.id === selected);
  if (!cases.length) throw Error('Requested case absent from bundle');
  return cases;
}

async function main() {
  const o = options(process.argv.slice(2));
  if (!o) return;
  const trust = read(o.trust, MAX_TRUST_BYTES);
  if (!object(trust) || trust.format !== 'vcp-evidence-demo-trust/1' || !object(trust.cases))
    throw Error('Unsupported trust configuration');
  let supplied; let cases;
  if (o.mode === 'bundle') cases = bundleCases(read(o.bundle), o.caseId);
  else {
    if (o.mode === 'response-file') supplied = read(o.responseFile);
    else {
      const url = new URL(o.apiUrl);
      if (url.username || url.password || url.hash || (url.protocol !== 'https:' &&
          !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))))
        throw Error('API URL must be HTTPS or loopback HTTP, without credentials or fragment');
      const response = await fetch(url, { headers: { Accept: 'application/json',
        'User-Agent': 'VCP-Evidence-Replay/0.1 (+https://github.com/veritaschain/vcp-sdk)' },
        redirect: 'error', signal: AbortSignal.timeout(15000) });
      if (!response.ok) {
        const body = await responseText(response, 512, true);
        if (response.status === 403 && /1010|cloudflare/i.test(body))
          throw Error('HTTP 403/Cloudflare host access control, not an INVALID cryptographic verdict');
        throw Error('HTTP ' + response.status + ', not a cryptographic verification verdict');
      }
      if ((response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
        await response.body?.cancel(); throw Error('Expected application/json');
      }
      supplied = parseJson(await responseText(response, MAX_INPUT_BYTES));
    }
    if (!object(supplied) || supplied.format !== 'vcp-evidence-demo-verification/1' ||
        typeof supplied.case_id !== 'string' || !Object.hasOwn(expected, supplied.case_id) ||
        !object(supplied.evidence)) throw Error('Not a fixed Explorer evidence verification response');
    if (o.caseId && o.caseId !== supplied.case_id) throw Error('Response case mismatch');
    for (const value of [supplied.local_status, supplied.overall_status])
      if (!['VALID', 'INVALID', 'INDETERMINATE'].includes(value)) throw Error('Malformed API verdict');
    if (supplied.sdk !== undefined && (!object(supplied.sdk) || supplied.sdk.version !== VERSION ||
        supplied.sdk.spec_version !== VCP_SPEC_VERSION || supplied.sdk.spec_commit !== VCP_SPEC_COMMIT))
      throw Error('Unsupported response SDK/specification declaration');
    cases = [{ ...supplied.evidence, id: supplied.case_id }];
  }
  // Baseline is the checked-out repository fixture, never an HTTP response.
  const baseline = bundleCases(read(resolve(root, 'examples/explorer-demo/bundle.json')), null);
  const results = cases.map(c => {
    if (!Object.hasOwn(trust.cases, c.id)) throw Error('Missing independently selected trust policy');
    const r = replay(c, trust.cases[c.id]); const wanted = expected[c.id];
    r.matches_expected_outcome = r.local_status === wanted[0] && r.overall_status === wanted[1];
    // Compatibility alias: outcome match only, NOT fixture identity.
    r.matches_fixed_demo = r.matches_expected_outcome;
    const original = baseline.find(x => x.id === c.id);
    r.fixture_bytes_match = ['events_jsonl', 'anchor_record_json', 'inclusion_proofs']
      .every(key => isDeepStrictEqual(c[key], original[key]));
    if (o.mode !== 'bundle') r.matches_api_claim = r.local_status === supplied.local_status &&
      r.overall_status === supplied.overall_status;
    return r;
  });
  const success = results.every(r => r.matches_expected_outcome && r.fixture_bytes_match && r.matches_api_claim !== false);
  if (o.json) process.stdout.write(JSON.stringify({ format: 'vcp-evidence-demo-offline-replay/1',
    input_source: o.mode, first_party: true, external_anchor_verified: false, success, results }, null, 2) + '\n');
  else {
    for (const r of results) process.stdout.write(r.id + ': local=' + r.local_status + ' overall=' + r.overall_status +
      ' expected-outcome=' + (r.matches_expected_outcome ? 'MATCH' : 'MISMATCH') +
      ' fixture-bytes=' + (r.fixture_bytes_match ? 'MATCH' : 'MISMATCH') +
      (o.mode !== 'bundle' ? ' API-claim=' + (r.matches_api_claim ? 'MATCH' : 'MISMATCH') : '') + '\n');
    process.stdout.write('First-party fixed-fixture replay only. External anchoring, real-world identity, completeness and conformance remain unverified.\n');
  }
  if (!success) process.exitCode = 1;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  main().catch(error => { process.stderr.write('Evidence replay error: ' + String(error.message || error) + '\n'); process.exitCode = 2; });
