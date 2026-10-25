/**
 * Ed25519 (RFC 8032) for events and Merkle roots.
 *
 * Event signatures sign the ASCII bytes of the bare hex EventHash (VCP v1.0
 * section 6.2.2); root signatures sign the 32 decoded root bytes (VCP v1.2
 * section 6.3.1). See INTERPRETATIONS.md I-5.
 *
 * Verification rule, identical to the Python package (which uses OpenSSL):
 * the public key must be a canonical encoding of a point in the prime-order
 * subgroup other than the identity (small-order points and points with a
 * torsion component are rejected); S must be below the group order L; and the check is cofactorless:
 * encode([S]B - [k]A) must equal the R bytes, with k = SHA-512(R || A || M) mod L.
 * (`@noble/curves`' own `verify` uses a cofactored equation, which accepts
 * signatures whose R has a small-order component; it is not used here.)
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concat, equal, fromBase64, fromHex, toBase64 } from "./bytes.js";
import { parseHash } from "./hashing.js";

const Point = ed25519.Point;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

export class KeyRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyRejected";
  }
}

function decodeKey(k: unknown): Uint8Array {
  let raw: Uint8Array | null;
  if (k instanceof Uint8Array) raw = k;
  else if (typeof k === "string" && /^[0-9a-fA-F]{64}$/.test(k)) raw = fromHex(k);
  else if (typeof k === "string") raw = fromBase64(k);
  else throw new KeyRejected("key must be a string or Uint8Array");
  if (!raw) throw new KeyRejected("key is neither 64-char hex nor canonical base64");
  if (raw.length !== 32) throw new KeyRejected(`Ed25519 keys are 32 bytes, got ${raw.length}`);
  return raw;
}

function leInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/** Why `raw` is not an acceptable Ed25519 public key, or null if it is. */
export function publicKeyProblem(raw: Uint8Array): string | null {
  let p;
  try {
    p = Point.fromBytes(raw, false);
  } catch {
    return "not a canonical encoding of a curve point";
  }
  if (!equal(p.toBytes(), raw)) return "not a canonical encoding of a curve point";
  if (p.isSmallOrder()) return "small-order point";
  if (!p.isTorsionFree()) return "point has a small-order (torsion) component";
  return null;
}

export class VerifyKey {
  readonly raw: Uint8Array;
  private readonly point: ReturnType<typeof Point.fromBytes>;
  constructor(publicKey: string | Uint8Array) {
    this.raw = decodeKey(publicKey);
    const problem = publicKeyProblem(this.raw);
    if (problem) throw new KeyRejected(`public key rejected: ${problem}`);
    this.point = Point.fromBytes(this.raw, false);
  }
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    if (signature.length !== 64) return false;
    const r = signature.subarray(0, 32);
    const s = leInt(signature.subarray(32, 64));
    if (s >= L) return false;
    const k = leInt(sha512(concat(r, this.raw, message))) % L;
    try {
      const rp = Point.BASE.multiplyUnsafe(s).subtract(this.point.multiplyUnsafe(k));
      return equal(rp.toBytes(), r);
    } catch {
      return false;
    }
  }
  toBase64(): string {
    return toBase64(this.raw);
  }
}

export class SigningKey {
  private readonly seed: Uint8Array;
  readonly verifyKey: VerifyKey;
  constructor(seed: string | Uint8Array) {
    this.seed = decodeKey(seed);
    this.verifyKey = new VerifyKey(ed25519.getPublicKey(this.seed));
  }
  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.seed);
  }
  seedBase64(): string {
    return toBase64(this.seed);
  }
}

export function generateKey(): SigningKey {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  return new SigningKey(seed);
}

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

function sig64(b64: unknown): Uint8Array | null {
  if (typeof b64 !== "string") return null;
  const s = fromBase64(b64);
  return s && s.length === 64 ? s : null;
}

export function signEventHash(eventHash: string, key: SigningKey): string {
  return toBase64(key.sign(ascii(parseHash(eventHash))));
}

export function verifyEventSignature(eventHash: string, signatureB64: string, key: VerifyKey): boolean {
  const s = sig64(signatureB64);
  return s !== null && key.verify(s, ascii(parseHash(eventHash)));
}

export function signMerkleRoot(merkleRoot: string, key: SigningKey): string {
  return toBase64(key.sign(fromHex(parseHash(merkleRoot))));
}

export function verifyRootSignature(merkleRoot: string, signatureB64: string, key: VerifyKey): boolean {
  const s = sig64(signatureB64);
  return s !== null && key.verify(s, fromHex(parseHash(merkleRoot)));
}
