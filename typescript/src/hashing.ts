/**
 * EventHash (VCP v1.2 section 6.1): H( JCS(Header) || JCS(Payload) [|| PrevHash hex] ),
 * concatenated as strings and UTF-8 encoded. See INTERPRETATIONS.md I-2 and I-3
 * for the hash-string forms.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { canonicalizeString } from "./jcs.js";
import { toHex } from "./bytes.js";

export const ZERO_HASH = "0".repeat(64);

export class UnsupportedAlgorithm extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedAlgorithm";
  }
}

const HASHERS: Record<string, (b: Uint8Array) => Uint8Array> = Object.assign(Object.create(null), {
  SHA256: (b: Uint8Array) => sha256(b),
  SHA3_256: (b: Uint8Array) => sha3_256(b),
  BLAKE3: (b: Uint8Array) => blake3(b),
});

export const SUPPORTED_HASH_ALGOS: readonly string[] = Object.keys(HASHERS);

/** Bare lowercase hex digest from `<hex>` or `sha256:<hex>`. */
export function parseHash(value: unknown): string {
  if (typeof value !== "string") throw new Error("hash must be a string");
  const body = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(body) || body.length !== 64) throw new Error(`not a 32-byte hex digest: ${JSON.stringify(value)}`);
  return body.toLowerCase();
}

/** Value to store in `Security.EventHash`: `sha256:<hex>` for SHA256, bare hex otherwise. */
export function formatEventHash(hex: string, algo = "SHA256"): string {
  return (algo === "SHA256" ? "sha256:" : "") + parseHash(hex);
}

export interface EventHashOptions {
  prevHash?: string | null;
  algo?: string;
  strictIntegers?: boolean;
}

/** Compute the EventHash; returns the bare lowercase hex digest. */
export function computeEventHash(header: object, payload: object, opts: EventHashOptions = {}): string {
  const algo: unknown = opts.algo ?? "SHA256";
  const h = typeof algo === "string" && Object.prototype.hasOwnProperty.call(HASHERS, algo) ? HASHERS[algo] : undefined;
  if (!h) throw new UnsupportedAlgorithm(`hash algorithm not supported: ${JSON.stringify(String(algo))}`);
  const strict = { strict: opts.strictIntegers ?? false };
  let input = canonicalizeString(header, strict) + canonicalizeString(payload, strict);
  if (opts.prevHash != null) {
    const prev = parseHash(opts.prevHash);
    if (prev !== ZERO_HASH) input += prev;
  }
  return toHex(h(new TextEncoder().encode(input)));
}
