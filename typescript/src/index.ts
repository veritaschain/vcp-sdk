/**
 * @veritaschain/vcp — offline core for VeritasChain Protocol (VCP) v1.2 events.
 *
 * Pre-release (0.x). First-party software from VSO / VeritasChain Co., Ltd.:
 * not an external or independent implementation, not certified, and a VALID
 * result is not a VCP conformance claim. See README.md and INTERPRETATIONS.md.
 */

export const VERSION = "0.1.0";
export const VCP_SPEC_VERSION = "1.2.0";
export const VCP_SPEC_COMMIT = "b23acb266f88df81d960d36d58fb64ceaa0dd5ed";

export { parseJson, parseJsonLines, StrictJSONError, MAX_DEPTH, MAX_INT_DIGITS } from "./json.js";
export type { JsonValue } from "./json.js";
export { canonicalize, canonicalizeString, formatNumber, differsFromRfc8785, CanonicalizationError } from "./jcs.js";
export { computeEventHash, formatEventHash, parseHash, UnsupportedAlgorithm, ZERO_HASH, SUPPORTED_HASH_ALGOS } from "./hashing.js";
export {
  MerkleTree,
  merkleRoot,
  leafHash,
  nodeHash,
  verifyInclusion,
  verifyConsistency,
  legacyExampleRoot,
} from "./merkle.js";
export {
  SigningKey,
  VerifyKey,
  KeyRejected,
  publicKeyProblem,
  generateKey,
  signEventHash,
  verifyEventSignature,
  signMerkleRoot,
  verifyRootSignature,
} from "./signing.js";
export { uuid7, nowNs, isoFromNs, nsFromIso, isoMatchesNs } from "./timeutil.js";
export { Producer, sealEvent, buildBatch, anchorRecord } from "./producer.js";
export type { VcpEvent, Batch, ProducerOptions } from "./producer.js";
export {
  VALID,
  INVALID,
  INDETERMINATE,
  combine,
  verifyEvent,
  verifyBatch,
  verifyChain,
  verifyInclusionProof,
  EVENT_TYPES,
} from "./verify.js";
export type { Check, Report, Status, KeyInput, BatchOptions, ExternalVerifier } from "./verify.js";
export { toHex, fromHex, toBase64, fromBase64 } from "./bytes.js";

import { canonicalizeString } from "./jcs.js";

/**
 * Serialise a value (including bigint TimestampInt) as JSON. Uses the canonical
 * form, which is valid JSON; JSON.stringify cannot serialise bigint.
 */
export function toJson(value: unknown): string {
  return canonicalizeString(value);
}
