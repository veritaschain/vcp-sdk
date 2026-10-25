/**
 * Offline verification with three-valued results (VALID / INVALID /
 * INDETERMINATE). Same checks, names, reason codes and decisions as the Python
 * verifier (python/src/veritaschain_vcp/verify.py); both are run against
 * test-vectors/hostile.json. INDETERMINATE is not a pass.
 *
 * A check this module does not perform is not reported as VALID. An unexpected
 * exception gives an INDETERMINATE report with reason VERIFIER_ERROR.
 */

import { computeEventHash, parseHash, UnsupportedAlgorithm, ZERO_HASH } from "./hashing.js";
import { CanonicalizationError, differsFromRfc8785 } from "./jcs.js";
import { legacyExampleRoot, merkleRoot, verifyInclusion } from "./merkle.js";
import { VerifyKey, verifyEventSignature, verifyRootSignature } from "./signing.js";
import { isoMatchesNs } from "./timeutil.js";
import { fromHex, toHex } from "./bytes.js";

export const VALID = "VALID";
export const INVALID = "INVALID";
export const INDETERMINATE = "INDETERMINATE";
export type Status = typeof VALID | typeof INVALID | typeof INDETERMINATE;
const RANK: Record<Status, number> = { VALID: 0, INDETERMINATE: 1, INVALID: 2 };

export const EVENT_TYPES: ReadonlySet<string> = new Set(
  ("INIT SIG ORD ACK EXE CXL MOD RSK ERR HBT CLS ANC " +
    "ERR_CONN ERR_AUTH ERR_TIMEOUT ERR_REJECT ERR_PARSE ERR_SYNC ERR_RISK ERR_SYSTEM ERR_RECOVER " +
    "ERASURE SYS_RECOVERY_ANNOUNCE SYS_CHECKPOINT SYS_AUDIT SYS_ANCHOR_MIGRATION SYS_ANCHOR_FAILOVER").split(" "),
);
const ANCHOR_TYPES: ReadonlySet<string> = new Set(["BLOCKCHAIN", "TSA", "DATABASE", "PUBLIC_SERVICE"]);
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEADER_STR = ["EventID", "TimestampISO", "EventType", "ActorID", "ChainID", "PolicyID"];
const HEADER_INT = ["TimestampInt", "SequenceNum"];
const SEC_STR_OPTIONAL = ["Version", "HashAlgo", "PrevHash", "Signature", "MerkleRoot", "AnchorReference", "AnchorRef", "PQCSignature", "PQCSignAlgo"];

export interface Check {
  name: string;
  status: Status;
  reason?: string;
  detail?: string;
  subject?: string;
}

export interface Report {
  status: Status;
  checks: Check[];
  notes: string[];
}

export type KeyInput = VerifyKey | string | Uint8Array | Record<string, VerifyKey | string | Uint8Array> | null | undefined;
export type ExternalVerifier = (record: Record<string, unknown>) => boolean | null | undefined;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Uint8Array);
const has = (o: Obj, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const hdr = (e: unknown): Obj => (isObj(e) && isObj(e.Header) ? e.Header : {});
const sec = (e: unknown): Obj => (isObj(e) && isObj(e.Security) ? e.Security : {});

export function combine(statuses: Status[]): Status {
  if (statuses.length === 0) return INDETERMINATE;
  return statuses.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
}

function report(checks: Check[], notes: string[]): Report {
  return { status: combine(checks.map((c) => c.status)), checks, notes: [...new Set(notes)] };
}

interface Ctx {
  checks: Check[];
  notes: string[];
}

/**
 * Run a verifier so that an unexpected exception cannot hide results: checks
 * completed before it are kept (an INVALID among them still makes the report
 * INVALID) and a VERIFIER_ERROR check is added.
 */
function guarded<A extends unknown[]>(fn: (ctx: Ctx, ...args: A) => Report): (...args: A) => Report {
  return (...args: A) => {
    const ctx: Ctx = { checks: [], notes: [] };
    try {
      return fn(ctx, ...args);
    } catch (err) {
      let detail = "error";
      try {
        detail = `${(err as Error)?.name}: ${(err as Error)?.message}`;
      } catch {
        /* keep the default */
      }
      return report([...ctx.checks, { name: "verifier", status: INDETERMINATE, reason: "VERIFIER_ERROR", detail }], ctx.notes);
    }
  };
}

/** A value for an error message; never throws (bigint, null-prototype objects). */
function show(v: unknown): string {
  try {
    if (typeof v === "bigint") return v.toString();
    const j = JSON.stringify(v);
    return j === undefined ? String(v) : j;
  } catch {
    return "(unprintable value)";
  }
}

function check(name: string, status: Status, reason?: string | null, detail?: string | null, subject?: string | null): Check {
  const c: Check = { name, status };
  if (reason) c.reason = reason;
  if (detail) c.detail = detail;
  if (subject) c.subject = subject;
  return c;
}

/** A JSON integer: a bigint, or a finite number with an integral value (JSON Schema semantics). */
function isInt(v: unknown): v is number | bigint {
  return typeof v === "bigint" || (typeof v === "number" && Number.isFinite(v) && Number.isInteger(v));
}
const big = (v: number | bigint): bigint => (typeof v === "bigint" ? v : BigInt(v));

function safeHex(v: unknown): string | null {
  try {
    return parseHash(v);
  } catch {
    return null;
  }
}

function keyFor(keys: KeyInput, actor: unknown): [VerifyKey | null, string | null] {
  if (keys == null) return [null, null];
  try {
    if (keys instanceof VerifyKey) return [keys, null];
    if (typeof keys === "string" || keys instanceof Uint8Array) return [new VerifyKey(keys), null];
    if (typeof actor !== "string" || !isObj(keys) || !has(keys, actor)) return [null, null];
    const k = (keys as Record<string, unknown>)[actor];
    if (k == null) return [null, null];
    if (k instanceof VerifyKey) return [k, null];
    if (typeof k === "string" || k instanceof Uint8Array) return [new VerifyKey(k), null];
    return [null, "key must be a string or Uint8Array"];
  } catch (err) {
    return [null, String((err as Error).message)];
  }
}

function structure(e: unknown, subject: string | null): Check {
  const bad = (reason: string, detail: string): Check => check("structure", INVALID, reason, detail, subject);
  if (!isObj(e)) return bad("NOT_AN_OBJECT", "event is not a JSON object");
  for (const part of ["Header", "Payload", "Security"]) {
    if (!isObj(e[part])) return bad("MISSING_FIELD", `${part} object missing`);
  }
  const h = e.Header as Obj;
  const s = e.Security as Obj;
  for (const f of HEADER_STR) {
    if (typeof h[f] !== "string" || h[f] === "") return bad("MISSING_FIELD", `Header.${f} missing or not a string`);
  }
  for (const f of HEADER_INT) {
    const v = h[f];
    if (!isInt(v) || big(v) < 0n) return bad("MISSING_FIELD", `Header.${f} missing or not a non-negative integer`);
  }
  if (!UUID.test(h.EventID as string)) return bad("BAD_FORMAT", "Header.EventID is not a UUID");
  if (has(h, "TraceID") && !(typeof h.TraceID === "string" && UUID.test(h.TraceID))) return bad("BAD_FORMAT", "Header.TraceID is not a UUID");
  if (!EVENT_TYPES.has(h.EventType as string)) return bad("UNKNOWN_EVENT_TYPE", `EventType ${show(h.EventType)} is not in the v1.2 registry`);
  for (const f of ["EventHash", "SignAlgo"]) {
    if (typeof s[f] !== "string" || s[f] === "") return bad("MISSING_FIELD", `Security.${f} missing or not a string`);
  }
  for (const f of SEC_STR_OPTIONAL) {
    if (has(s, f) && typeof s[f] !== "string") return bad("BAD_FORMAT", `Security.${f} is not a string`);
  }
  if (has(s, "PrevHash") && safeHex(s.PrevHash) === null) return bad("BAD_FORMAT", "Security.PrevHash is not a 32-byte hex digest");
  if (has(s, "MerkleRoot") && safeHex(s.MerkleRoot) === null) return bad("BAD_FORMAT", "Security.MerkleRoot is not a 32-byte hex digest");
  if (has(s, "MerkleIndex") && !(isInt(s.MerkleIndex) && big(s.MerkleIndex) >= 0n)) return bad("BAD_FORMAT", "Security.MerkleIndex is not a non-negative integer");
  if (has(e, "PolicyIdentification") && !isObj(e.PolicyIdentification)) return bad("BAD_FORMAT", "PolicyIdentification is not an object");
  return check("structure", VALID, null, null, subject);
}

function eventChecks(e: unknown, keys: KeyInput, notes: string[], requireSignAlgo: string | null, checks: Check[]): string | null {
  const sid = typeof hdr(e).EventID === "string" ? (hdr(e).EventID as string) : null;
  const st = structure(e, sid);
  checks.push(st);
  if (st.status !== VALID) return null;
  const ev = e as Obj;
  const h = ev.Header as Obj;
  const p = ev.Payload as Obj;
  const s = ev.Security as Obj;

  try {
    const ok = isoMatchesNs(h.TimestampISO as string, big(h.TimestampInt as number | bigint));
    checks.push(check("timestamp", ok ? VALID : INVALID, ok ? null : "TIMESTAMP_MISMATCH", ok ? null : "TimestampISO and TimestampInt disagree", sid));
  } catch (err) {
    checks.push(check("timestamp", INVALID, "BAD_FORMAT", String((err as Error).message), sid));
  }

  if (differsFromRfc8785(h) || differsFromRfc8785(p)) {
    notes.push(
      "Some events contain integers above 2**53 (typically TimestampInt). They were hashed as their " +
        "exact decimal digits (INTERPRETATIONS.md I-4); an implementation that applies RFC 8785 to " +
        "integers would round, reject or reformat them and compute a different EventHash.",
    );
  }

  if (has(ev, "PolicyIdentification")) {
    notes.push("PolicyIdentification is outside EventHash (VCP v1.2 section 6.1.1); its contents are not integrity-checked.");
    if ((ev.PolicyIdentification as Obj).PolicyID !== h.PolicyID) {
      checks.push(check("policy_id", INVALID, "POLICY_MISMATCH", "PolicyIdentification.PolicyID differs from Header.PolicyID", sid));
    }
  }

  let algo: string;
  if (has(s, "HashAlgo")) algo = s.HashAlgo as string;
  else {
    algo = "SHA256";
    notes.push("Security.HashAlgo absent; SHA256 (the section 1.5.2 default) was assumed.");
  }
  let recomputed: string | null = null;
  const claimed = s.EventHash as string;
  const claimedHex = safeHex(claimed);
  if (claimed.startsWith("sha256:") && algo !== "SHA256") {
    checks.push(check("event_hash", INVALID, "HASH_FORMAT_MISMATCH", `sha256: prefix with HashAlgo ${show(algo)}`, sid));
  } else if (claimedHex === null) {
    checks.push(check("event_hash", INVALID, "BAD_FORMAT", "Security.EventHash is not a 32-byte hex digest", sid));
  } else {
    try {
      recomputed = computeEventHash(h, p, { prevHash: has(s, "PrevHash") ? (s.PrevHash as string) : null, algo });
      const ok = recomputed === claimedHex;
      checks.push(check("event_hash", ok ? VALID : INVALID, ok ? null : "HASH_MISMATCH", ok ? null : "recomputed EventHash differs from Security.EventHash", sid));
    } catch (err) {
      if (err instanceof UnsupportedAlgorithm) checks.push(check("event_hash", INDETERMINATE, "ALGORITHM_UNSUPPORTED", err.message, sid));
      else if (err instanceof CanonicalizationError) checks.push(check("event_hash", INDETERMINATE, "CANONICALIZATION_UNSUPPORTED", err.message, sid));
      else throw err;
    }
  }

  const sig = has(s, "Signature") ? s.Signature : undefined;
  const signAlgo = s.SignAlgo as string;
  if (requireSignAlgo != null && signAlgo !== requireSignAlgo) {
    checks.push(check("signature", INVALID, "ALGORITHM_MISMATCH", `SignAlgo ${show(signAlgo)} but ${requireSignAlgo} is required by the caller`, sid));
  } else if (sig === undefined) {
    checks.push(check("signature", INDETERMINATE, "MISSING_SIGNATURE", "no Security.Signature (it may be carried by a COSE envelope, which this SDK does not read)", sid));
  } else if (signAlgo !== "ED25519") {
    checks.push(check("signature", INDETERMINATE, "ALGORITHM_UNSUPPORTED", `SignAlgo ${show(signAlgo)}`, sid));
  } else {
    const [key, problem] = keyFor(keys, h.ActorID);
    if (!key) {
      checks.push(check("signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", problem ?? `no trusted public key supplied for ActorID ${show(h.ActorID)}`, sid));
    } else if (recomputed === null) {
      checks.push(check("signature", INDETERMINATE, "HASH_NOT_RECOMPUTED", "the signature is checked against the recomputed EventHash, which is unavailable", sid));
    } else {
      const ok = verifyEventSignature(recomputed, sig as string, key);
      checks.push(check("signature", ok ? VALID : INVALID, ok ? null : "SIGNATURE_MISMATCH", null, sid));
    }
  }
  if (has(s, "PQCSignature")) notes.push("PQCSignature present; post-quantum signatures are not verified by this SDK.");
  return recomputed !== null && recomputed === claimedHex ? recomputed : null;
}

/** Verify one event. `requireSignAlgo` (e.g. "ED25519") makes a different SignAlgo INVALID instead of INDETERMINATE. */
export const verifyEvent = guarded((ctx: Ctx, event: unknown, publicKey: KeyInput = null, requireSignAlgo: string | null = null): Report => {
  eventChecks(event, publicKey, ctx.notes, requireSignAlgo, ctx.checks);
  return report(ctx.checks, ctx.notes);
});

/**
 * Verify an RFC 6962 inclusion proof against a root. Without `rootAuthenticated`
 * the report carries an INDETERMINATE `root_authenticity` check; with it, that
 * check is omitted and a note records that the SDK did not perform it.
 */
export const verifyInclusionProof = guarded(
  (_ctx: Ctx, eventHash: unknown, index: unknown, treeSize: unknown, proof: unknown, root: unknown, rootAuthenticated: boolean = false): Report => {
    const notes: string[] = [];
    const intArg = (v: unknown): boolean => typeof v === "bigint" || (typeof v === "number" && Number.isSafeInteger(v));
    if (!intArg(index) || !intArg(treeSize)) return report([check("inclusion", INVALID, "BAD_FORMAT", "index and tree_size must be integers")], notes);
    if (!Array.isArray(proof) || !proof.every((x) => typeof x === "string")) {
      return report([check("inclusion", INVALID, "BAD_FORMAT", "proof must be a list of hex strings")], notes);
    }
    const leaf = safeHex(eventHash), r = safeHex(root);
    const path = (proof as string[]).map(safeHex);
    if (leaf === null || r === null || path.some((x) => x === null)) {
      return report([check("inclusion", INVALID, "BAD_FORMAT", "a hash is not a 32-byte hex digest")], notes);
    }
    const ok = verifyInclusion(fromHex(leaf), index as number | bigint, treeSize as number | bigint, path.map((x) => fromHex(x!)), fromHex(r));
    const checks = [check("inclusion", ok ? VALID : INVALID, ok ? null : "PROOF_MISMATCH")];
    if (rootAuthenticated === true) notes.push("The caller stated that the Merkle root and tree size were authenticated; this SDK did not check that.");
    else checks.push(check("root_authenticity", INDETERMINATE, "ROOT_NOT_AUTHENTICATED", "the Merkle root and tree size were not authenticated by a verified anchor"));
    return report(checks, notes);
  },
);

export interface BatchOptions {
  publicKey?: KeyInput;
  anchorPublicKey?: VerifyKey | string | Uint8Array | null;
  externalAnchorVerifier?: ExternalVerifier | null;
  requireSignAlgo?: string | null;
}

export const verifyBatch = guarded((ctx: Ctx, events: unknown, anchorRecord: unknown, opts: BatchOptions = {}): Report => {
  const notes = ctx.notes;
  notes.push(
    "Completeness is shown only relative to the anchored root, at anchor granularity: " +
      "an event that was never included in the batch is not detectable here.",
    "Security.AnchorReference is not checked by this SDK.",
  );
  const checks = ctx.checks;
  if (!Array.isArray(events)) return report([check("batch", INVALID, "BAD_FORMAT", "events must be a list")], notes);
  if (events.length === 0) return report([check("batch", INVALID, "EMPTY_BATCH", "no events supplied")], notes);
  const requireSignAlgo = opts.requireSignAlgo ?? null;
  const hashes: (string | null)[] = [];
  for (const e of events) hashes.push(eventChecks(e, opts.publicKey ?? null, notes, requireSignAlgo, checks));
  let treeRoot: string | null = null;
  let legacy: string | null = null;
  if (hashes.some((h) => h === null)) {
    checks.push(check("merkle_root", INDETERMINATE, "HASH_NOT_RECOMPUTED", "the tree cannot be rebuilt because some EventHash values could not be confirmed"));
  } else {
    const leaves = hashes.map((h) => fromHex(h!));
    treeRoot = toHex(merkleRoot(leaves));
    legacy = toHex(legacyExampleRoot(leaves));
    let missing = 0;
    events.forEach((e, i) => {
      const s = sec(e);
      const sid = hdr(e).EventID as string | undefined;
      if (!has(s, "MerkleRoot") || !has(s, "MerkleIndex")) missing++;
      if (has(s, "MerkleRoot")) {
        const er = safeHex(s.MerkleRoot);
        if (er === legacy && er !== treeRoot) {
          checks.push(check("event_merkle_root", INDETERMINATE, "LEGACY_MERKLE_CONSTRUCTION", "Security.MerkleRoot matches the section 6.2.1 example construction, not RFC 6962", sid));
        } else if (er !== treeRoot) {
          checks.push(check("event_merkle_root", INVALID, "MERKLE_FIELD_MISMATCH", "Security.MerkleRoot differs from the batch root", sid));
        }
      }
      if (has(s, "MerkleIndex") && big(s.MerkleIndex as number | bigint) !== BigInt(i)) {
        checks.push(check("event_merkle_index", INVALID, "MERKLE_FIELD_MISMATCH", `Security.MerkleIndex ${show(s.MerkleIndex)} but position ${i}`, sid));
      }
    });
    if (missing) {
      checks.push(check("event_merkle_fields", INDETERMINATE, "MISSING_FIELD",
        `${missing} event(s) lack Security.MerkleRoot or MerkleIndex (REQUIRED from v1.1, section 6.4.1); their placement in the batch was not checked`));
    }
  }

  if (anchorRecord === null || anchorRecord === undefined) {
    checks.push(check("anchor_record", INDETERMINATE, "MISSING_ANCHOR_RECORD"));
    return report(checks, notes);
  }
  if (!isObj(anchorRecord)) {
    checks.push(check("anchor_record", INVALID, "BAD_FORMAT", "AnchorRecord is not a JSON object"));
    return report(checks, notes);
  }
  const rec = anchorRecord;
  const recRoot = safeHex(rec.MerkleRoot);
  if (recRoot === null) checks.push(check("merkle_root", INVALID, "BAD_FORMAT", "AnchorRecord.MerkleRoot is not a 32-byte hex digest"));
  else if (treeRoot !== null) {
    if (treeRoot === recRoot) checks.push(check("merkle_root", VALID));
    else if (legacy === recRoot) {
      checks.push(check("merkle_root", INDETERMINATE, "LEGACY_MERKLE_CONSTRUCTION",
        "the root matches the VCP v1.2 section 6.2.1 example construction (odd node duplicated), not RFC 6962; this SDK does not verify that construction"));
    } else checks.push(check("merkle_root", INVALID, "ROOT_MISMATCH", "the supplied events do not reproduce AnchorRecord.MerkleRoot"));
  }

  const sig = has(rec, "Signature") ? rec.Signature : undefined;
  const signAlgo = rec.SignAlgo;
  let anchorKey: KeyInput = opts.anchorPublicKey ?? null;
  const pk = opts.publicKey;
  let defaultedKey = false;
  if (anchorKey == null && (pk instanceof VerifyKey || typeof pk === "string" || pk instanceof Uint8Array)) {
    anchorKey = pk;
    defaultedKey = true;
  }
  if (requireSignAlgo != null && signAlgo !== requireSignAlgo) {
    checks.push(check("root_signature", INVALID, "ALGORITHM_MISMATCH", `SignAlgo ${show(signAlgo)} but ${requireSignAlgo} is required`));
  } else if (sig === undefined || sig === null) checks.push(check("root_signature", INDETERMINATE, "MISSING_SIGNATURE"));
  else if (typeof sig !== "string" || typeof signAlgo !== "string") checks.push(check("root_signature", INVALID, "BAD_FORMAT", "Signature and SignAlgo must be strings"));
  else if (signAlgo !== "ED25519") checks.push(check("root_signature", INDETERMINATE, "ALGORITHM_UNSUPPORTED", `SignAlgo ${show(signAlgo)}`));
  else if (anchorKey == null) checks.push(check("root_signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", "no trusted key supplied for the AnchorRecord"));
  else if (recRoot === null) checks.push(check("root_signature", INDETERMINATE, "BAD_FORMAT", "no valid MerkleRoot to check the signature against"));
  else {
    const [k, problem] = keyFor(anchorKey, null);
    if (!k) checks.push(check("root_signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", problem ?? "key rejected"));
    else {
      const ok = verifyRootSignature(recRoot, sig, k);
      checks.push(check("root_signature", ok ? VALID : INVALID, ok ? null : "SIGNATURE_MISMATCH"));
      if (defaultedKey) notes.push("The AnchorRecord signature was verified against the same key as the events (no separate anchor key was supplied).");
    }
  }

  notes.push(
    "The AnchorRecord signature covers the Merkle root only (VCP v1.2 section 6.3.1); " +
      "EventCount, FirstEventID, LastEventID and PolicyID are checked against the supplied events, " +
      "and Timestamp for format only, not against a signature.",
  );
  const problems: string[] = [];
  const count = rec.EventCount;
  if (!(isInt(count) && big(count) === BigInt(events.length))) problems.push(`EventCount ${show(count)} but ${events.length} events supplied`);
  const sameId = (a: unknown, b: unknown): boolean => typeof a === "string" && typeof b === "string" && a === b;
  if (!sameId(rec.FirstEventID, hdr(events[0]).EventID)) problems.push("FirstEventID differs from the first event");
  if (!sameId(rec.LastEventID, hdr(events[events.length - 1]).EventID)) problems.push("LastEventID differs from the last event");
  const recPid = rec.PolicyID;
  if (typeof recPid !== "string" || events.some((e) => hdr(e).PolicyID !== recPid)) problems.push("PolicyID differs from the events' Header.PolicyID");
  checks.push(check("anchor_binding", problems.length ? INVALID : VALID, problems.length ? "BINDING_MISMATCH" : null, problems.join("; ") || null));

  const ts = rec.Timestamp;
  if (isInt(ts) && big(ts) >= 0n) checks.push(check("anchor_timestamp_format", VALID, null, "non-negative integer; the value is not checked and not covered by the signature"));
  else checks.push(check("anchor_timestamp_format", INVALID, "BAD_FORMAT", `Timestamp ${show(ts)} is not a non-negative integer`));

  if (!has(rec, "AnchorTarget")) {
    checks.push(check("external_anchor", INDETERMINATE, "MISSING_ANCHOR_PROOF", "no AnchorTarget; VCP v1.2 section 6.3.3 requires external anchoring"));
  } else {
    const target = rec.AnchorTarget;
    const proof = isObj(target) ? target.Proof : undefined;
    if (!isObj(target)) checks.push(check("external_anchor", INVALID, "BAD_FORMAT", "AnchorTarget is not an object"));
    else if (typeof target.Type !== "string" || !ANCHOR_TYPES.has(target.Type)) checks.push(check("external_anchor", INVALID, "BAD_FORMAT", `AnchorTarget.Type ${show(target.Type)}`));
    else if (proof !== undefined && proof !== null && typeof proof !== "string") checks.push(check("external_anchor", INVALID, "BAD_FORMAT", "AnchorTarget.Proof is not a string"));
    else if (!proof) checks.push(check("external_anchor", INDETERMINATE, "MISSING_ANCHOR_PROOF", "AnchorTarget.Proof is empty or absent"));
    else if (!opts.externalAnchorVerifier) {
      checks.push(check("external_anchor", INDETERMINATE, "EXTERNAL_ANCHOR_NOT_VERIFIED", "this SDK does not contact anchor targets; supply externalAnchorVerifier"));
    } else {
      let r: boolean | null | undefined = null;
      try {
        r = opts.externalAnchorVerifier(rec);
      } catch (err) {
        notes.push(`externalAnchorVerifier raised ${(err as Error)?.name}: ${(err as Error)?.message}`);
      }
      if (r === true) checks.push(check("external_anchor", VALID, null, "reported by the supplied externalAnchorVerifier"));
      else if (r === false) checks.push(check("external_anchor", INVALID, "ANCHOR_MISMATCH", "reported by the supplied externalAnchorVerifier"));
      else checks.push(check("external_anchor", INDETERMINATE, "ANCHOR_PENDING_OR_UNREACHABLE"));
    }
  }
  return report(checks, notes);
});

function linkHash(v: unknown): string | null {
  const h = safeHex(v);
  return h === null || h === ZERO_HASH ? null : h;
}

/**
 * SequenceNum continuity and PrevHash links for one ActorID/ChainID, in order.
 * Links without a PrevHash (or with the all-zero value) are INDETERMINATE,
 * except an INIT event at the start when no priorHash is given (a chain start).
 */
export const verifyChain = guarded((ctx: Ctx, events: unknown, priorHash: string | null = null): Report => {
  const notes = ctx.notes;
  const checks = ctx.checks;
  if (!Array.isArray(events)) return report([check("chain", INVALID, "BAD_FORMAT", "events must be a list")], notes);
  if (events.length === 0) return report([check("chain", INVALID, "EMPTY_CHAIN")], notes);
  let expectedPrior: string | null = null;
  let priorMalformed = false;
  if (priorHash != null) {
    expectedPrior = safeHex(priorHash);
    priorMalformed = expectedPrior === null;
  }
  let chainKey: [string, string] | null = null;
  let prevHex: string | null = null;
  let prevSeq: number | bigint | null = null;
  events.forEach((e: unknown, i: number) => {
    const st = structure(e, null);
    if (st.status !== VALID) {
      checks.push(st);
      prevHex = null;
      prevSeq = null;
      return;
    }
    const h = hdr(e);
    const s = sec(e);
    const sid = h.EventID as string;
    const key: [string, string] = [h.ActorID as string, h.ChainID as string];
    if (chainKey === null) chainKey = key;
    else if (key[0] !== chainKey[0] || key[1] !== chainKey[1]) checks.push(check("chain_identity", INVALID, "MIXED_CHAIN", "ActorID/ChainID differs within the sequence", sid));
    const seq = h.SequenceNum as number | bigint;
    if (i > 0) {
      if (prevSeq === null) checks.push(check("sequence", INDETERMINATE, "PREVIOUS_EVENT_INVALID", "the preceding event could not be read", sid));
      else if (big(seq) !== big(prevSeq) + 1n) checks.push(check("sequence", INVALID, "SEQUENCE_GAP", `SequenceNum ${show(seq)} after ${show(prevSeq)}`, sid));
      else checks.push(check("sequence", VALID, null, null, sid));
    }
    let thisHex: string | null = null;
    try {
      thisHex = computeEventHash(h, (e as Obj).Payload as Obj, {
        prevHash: has(s, "PrevHash") ? (s.PrevHash as string) : null,
        algo: has(s, "HashAlgo") ? (s.HashAlgo as string) : "SHA256",
      });
      if (thisHex !== safeHex(s.EventHash)) {
        checks.push(check("link_source", INVALID, "HASH_MISMATCH", "EventHash does not match the event", sid));
        thisHex = null;
      }
    } catch (err) {
      if (err instanceof UnsupportedAlgorithm || err instanceof CanonicalizationError) {
        checks.push(check("link_source", INDETERMINATE, "HASH_NOT_RECOMPUTED", err.message, sid));
      } else throw err;
    }
    const link = linkHash(s.PrevHash);
    const expected = i === 0 ? expectedPrior : prevHex;
    if (link === null) {
      if (i === 0 && priorHash == null && h.EventType === "INIT") checks.push(check("prev_hash", VALID, null, "chain start (INIT without PrevHash)", sid));
      else checks.push(check("prev_hash", INDETERMINATE, "CHAIN_NOT_USED", "no PrevHash on this event", sid));
    } else if (expected === null) {
      if (i === 0 && priorMalformed) checks.push(check("prev_hash", INDETERMINATE, "PRIOR_HASH_MALFORMED", "prior_hash is not a 32-byte hex digest", sid));
      else checks.push(check("prev_hash", INDETERMINATE, i === 0 ? "PRIOR_HASH_MISSING" : "PREVIOUS_HASH_UNAVAILABLE", "the hash of the preceding event is not available", sid));
    } else {
      const ok = link === expected;
      checks.push(check("prev_hash", ok ? VALID : INVALID, ok ? null : "CHAIN_BREAK", null, sid));
    }
    prevHex = thisHex;
    prevSeq = seq;
  });
  return report(checks, notes);
});
