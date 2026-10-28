#!/usr/bin/env node
/**
 * First-party, offline replay of the three fixed synthetic Explorer demo cases.
 * Results are recomputed with the local SDK; a server's verdict is never trusted.
 * No external-anchor proof, source identity, live-event completeness or
 * VCP/VAP conformance is established.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  VERSION, VCP_SPEC_VERSION, parseJson, parseJsonLines, parseHash,
  verifyBatch, verifyChain, verifyInclusionProof, computeEventHash, combine
} from '../typescript/dist/index.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const expected = {
  intact: ['VALID', 'INDETERMINATE'],
  tampered: ['INVALID', 'INVALID'],
  'missing-key': ['INDETERMINATE', 'INDETERMINATE']
};
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const equalHash = (a, b) => { try { return parseHash(a) === parseHash(b); } catch { return false; } };
const equalInt = (value, n) =>
  (typeof value === 'bigint' || (typeof value === 'number' && Number.isSafeInteger(value))) &&
  BigInt(value) === BigInt(n);
const read = path => JSON.parse(readFileSync(path, 'utf8'));

function options(argv) {
  const o = {
    bundle: resolve(root, 'examples/explorer-demo/bundle.json'),
    trust: resolve(root, 'examples/explorer-demo/trust.json'),
    responseFile: null, apiUrl: null, caseId: null, json: false
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') o.json = true;
    else if (arg === '--help') {
      process.stdout.write('Usage: node tools/replay_explorer_demo.mjs [--case intact|tampered|missing-key] [--bundle path] [--trust path] [--api-response path | --api-url https://.../verification] [--json]\nBuild first: npm --prefix typescript ci && npm --prefix typescript run build\n');
      return null;
    } else if (['--bundle', '--trust', '--api-response', '--api-url', '--case'].includes(arg)) {
      if (++i >= argv.length) throw Error('Missing value for ' + arg);
      if (arg === '--bundle') o.bundle = resolve(argv[i]);
      if (arg === '--trust') o.trust = resolve(argv[i]);
      if (arg === '--api-response') o.responseFile = resolve(argv[i]);
      if (arg === '--api-url') o.apiUrl = argv[i];
      if (arg === '--case') o.caseId = argv[i];
    } else throw Error('Unknown argument: ' + arg);
  }
  if (o.responseFile && o.apiUrl) throw Error('Choose only one API response source');
  if (o.caseId && !Object.hasOwn(expected, o.caseId)) throw Error('Unrecognized demo case');
  return o;
}

function replay(c, policy) {
  if (!object(c) || typeof c.events_jsonl !== 'string' ||
      typeof c.anchor_record_json !== 'string' || !Array.isArray(c.inclusion_proofs) ||
      !object(policy) || !object(policy.actor_public_keys)) {
    throw Error('Evidence strings, proofs and an explicit trust policy are required');
  }
  const events = parseJsonLines(c.events_jsonl);
  const record = parseJson(c.anchor_record_json);
  if (!Array.isArray(events) || events.length < 1 || events.length > 100 || !object(record))
    throw Error('Malformed or oversized fixed event batch');
  const checks = [];
  // An extra or duplicate detached proof must not be silently ignored.
  const proofIds = c.inclusion_proofs.map(p => p?.event_id);
  if (c.inclusion_proofs.length !== events.length || new Set(proofIds).size !== proofIds.length) {
    checks.push({ name: 'proof_binding', status: 'INVALID',
      reason: 'PROOF_SET_MISMATCH', group: 'inclusion', scope: 'local' });
  }
  function append(group, report) {
    for (const x of report.checks) checks.push({
      ...x, group,
      scope: x.name === 'external_anchor' || x.name === 'root_authenticity'
        ? 'external' : 'local'
    });
  }
  append('batch', verifyBatch(events, record, {
    publicKey: policy.actor_public_keys,
    anchorPublicKey: policy.anchor_public_key ?? null,
    requireSignAlgo: 'ED25519'
  }));
  append('chain', verifyChain(events));
  for (const [index, event] of events.entries()) {
    const s = event?.Security;
    const id = event?.Header?.EventID;
    if (typeof id !== 'string' || !object(s)) throw Error('Malformed event');
    const proof = c.inclusion_proofs.find(p => p?.event_id === id);
    if (!proof) {
      checks.push({ name: 'inclusion', status: 'INDETERMINATE',
        reason: 'MISSING_INCLUSION_PROOF', group: 'inclusion', scope: 'local', subject: id });
      continue;
    }
    const bound = proof.index === index && proof.tree_size === events.length &&
      equalInt(record.EventCount, events.length) && equalInt(s.MerkleIndex, index) &&
      equalHash(proof.event_hash, s.EventHash) &&
      equalHash(proof.merkle_root, s.MerkleRoot) &&
      equalHash(proof.merkle_root, record.MerkleRoot);
    checks.push({
      name: 'proof_binding', status: bound ? 'VALID' : 'INVALID',
      ...(bound ? {} : { reason: 'PROOF_BINDING_MISMATCH' }),
      group: 'inclusion', scope: 'local', subject: id
    });
    try {
      const hash = computeEventHash(event.Header, event.Payload, {
        prevHash: s.PrevHash, algo: s.HashAlgo
      });
      append('inclusion', verifyInclusionProof(
        hash, proof.index, proof.tree_size, proof.proof, proof.merkle_root, false
      ));
    } catch {
      checks.push({ name: 'inclusion', status: 'INDETERMINATE',
        reason: 'HASH_NOT_RECOMPUTED', group: 'inclusion', scope: 'local', subject: id });
    }
  }
  for (const p of c.inclusion_proofs) {
    if (!events.some(e => e?.Header?.EventID === p?.event_id))
      checks.push({ name: 'proof_binding', status: 'INVALID',
        reason: 'EVENT_NOT_IN_BATCH', group: 'inclusion', scope: 'local' });
  }
  return {
    id: c.id,
    local_status: combine(checks.filter(x => x.scope === 'local').map(x => x.status)),
    overall_status: combine(checks.map(x => x.status)),
    checks: checks.map(x => ({
      name: x.name, status: x.status, ...(x.reason ? { reason: x.reason } : {}),
      group: x.group, scope: x.scope
    }))
  };
}

async function main() {
  const o = options(process.argv.slice(2));
  if (!o) return;
  const trust = read(o.trust);
  if (trust.format !== 'vcp-evidence-demo-trust/1' || !object(trust.cases))
    throw Error('Unsupported trust configuration');
  let supplied = o.responseFile ? read(o.responseFile) : null;
  if (o.apiUrl) {
    const url = new URL(o.apiUrl);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' &&
        ['127.0.0.1', 'localhost'].includes(url.hostname))) {
      throw Error('API URL must use HTTPS or local loopback HTTP');
    }
    const response = await fetch(url, {
      headers: { Accept: 'application/json' },
      redirect: 'error', signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) {
      const body = (await response.text()).slice(0, 500);
      if (response.status === 403 && (body.includes('1010') || body.includes('Cloudflare')))
        throw Error('HTTP 403/Cloudflare host access control, not an INVALID cryptographic verdict; use the local bundle or a saved API response');
      throw Error('HTTP ' + response.status + ', not a cryptographic verification verdict');
    }
    supplied = await response.json();
  }
  let cases;
  if (supplied !== null) {
    if (supplied.format !== 'vcp-evidence-demo-verification/1' ||
        !Object.hasOwn(expected, supplied.case_id) || !object(supplied.evidence))
      throw Error('Not a fixed Explorer evidence verification response');
    if (o.caseId && o.caseId !== supplied.case_id) throw Error('Response case mismatch');
    cases = [{ ...supplied.evidence, id: supplied.case_id }];
  } else {
    const bundle = read(o.bundle);
    if (bundle.format !== 'vcp-evidence-demo/1' ||
        bundle.sdk_version !== VERSION || bundle.spec_version !== VCP_SPEC_VERSION ||
        !Array.isArray(bundle.cases)) throw Error('Unsupported fixed demo bundle');
    cases = bundle.cases.filter(c => !o.caseId || c.id === o.caseId);
  }
  if (cases.length < 1 || cases.length > 3) throw Error('Unexpected fixed demo case count');
  const results = cases.map(c => {
    if (!Object.hasOwn(expected, c.id) || !Object.hasOwn(trust.cases, c.id))
      throw Error('Unrecognized case or missing independently selected trust');
    const r = replay(c, trust.cases[c.id]);
    const e = expected[c.id];
    r.matches_fixed_demo = r.local_status === e[0] && r.overall_status === e[1];
    if (supplied) r.matches_api_claim = r.local_status === supplied.local_status &&
      r.overall_status === supplied.overall_status;
    return r;
  });
  const success = results.every(r => r.matches_fixed_demo && r.matches_api_claim !== false);
  if (o.json) {
    process.stdout.write(JSON.stringify({
      format: 'vcp-evidence-demo-offline-replay/1', first_party: true,
      external_anchor_verified: false, success, results
    }, null, 2) + '\n');
  } else {
    for (const r of results)
      process.stdout.write(r.id + ': local=' + r.local_status +
        ' overall=' + r.overall_status +
        ' fixture=' + (r.matches_fixed_demo ? 'MATCH' : 'MISMATCH') +
        (supplied ? ' API-claim=' + (r.matches_api_claim ? 'MATCH' : 'MISMATCH') : '') + '\n');
    process.stdout.write('First-party replay only. External anchoring, real-world identity, completeness and conformance remain unverified.\n');
  }
  if (!success) process.exitCode = 1;
}
main().catch(err => {
  process.stderr.write('Evidence replay error: ' + String(err.message || err) + '\n');
  process.exitCode = 2;
});
