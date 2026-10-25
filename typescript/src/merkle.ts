/**
 * RFC 6962 section 2.1 / RFC 9162 section 2.1 Merkle trees over decoded
 * 32-byte EventHash values. See INTERPRETATIONS.md I-1: the VCP v1.2
 * section 6.2.1 example code duplicates odd nodes; this module does not.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { concat, equal } from "./bytes.js";

const ZERO = new Uint8Array([0]);
const ONE = new Uint8Array([1]);

export const leafHash = (data: Uint8Array): Uint8Array => sha256(concat(ZERO, data));
export const nodeHash = (l: Uint8Array, r: Uint8Array): Uint8Array => sha256(concat(ONE, l, r));

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** An RFC 6962 tree over fixed leaf data, with cached subtree hashes. */
export class MerkleTree {
  readonly size: number;
  readonly root: Uint8Array;
  private readonly cache = new Map<string, Uint8Array>();

  constructor(private readonly leaves: readonly Uint8Array[]) {
    this.size = leaves.length;
    this.root = this.mth(0, this.size);
  }

  private mth(lo: number, hi: number): Uint8Array {
    const key = `${lo}:${hi}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const n = hi - lo;
    let h: Uint8Array;
    if (n === 0) h = sha256(new Uint8Array(0));
    else if (n === 1) h = leafHash(this.leaves[lo]!);
    else {
      const k = split(n);
      h = nodeHash(this.mth(lo, lo + k), this.mth(lo + k, hi));
    }
    this.cache.set(key, h);
    return h;
  }

  private path(m: number, lo: number, hi: number): Uint8Array[] {
    const n = hi - lo;
    if (n <= 1) return [];
    const k = split(n);
    if (m < k) return [...this.path(m, lo, lo + k), this.mth(lo + k, hi)];
    return [...this.path(m - k, lo + k, hi), this.mth(lo, lo + k)];
  }

  private subproof(m: number, lo: number, hi: number, b: boolean): Uint8Array[] {
    const n = hi - lo;
    if (m === n) return b ? [] : [this.mth(lo, hi)];
    const k = split(n);
    if (m <= k) return [...this.subproof(m, lo, lo + k, b), this.mth(lo + k, hi)];
    return [...this.subproof(m - k, lo + k, hi, false), this.mth(lo, lo + k)];
  }

  inclusionProof(index: number): Uint8Array[] {
    if (!(index >= 0 && index < this.size)) throw new RangeError("leaf index out of range");
    return this.path(index, 0, this.size);
  }

  consistencyProof(first: number): Uint8Array[] {
    if (!(first >= 0 && first <= this.size)) throw new RangeError("first size out of range");
    if (first === 0 || first === this.size) return [];
    return this.subproof(first, 0, this.size, true);
  }
}

export const merkleRoot = (leaves: readonly Uint8Array[]): Uint8Array => new MerkleTree(leaves).root;

/** RFC 9162 section 2.1.3.2. `leaf` is the leaf data (decoded EventHash). Index and size may be bigint. */
export function verifyInclusion(
  leaf: Uint8Array,
  index: number | bigint,
  treeSize: number | bigint,
  proof: readonly Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  const isIdx = (v: unknown): boolean => typeof v === "bigint" || (typeof v === "number" && Number.isSafeInteger(v));
  if (!isIdx(index) || !isIdx(treeSize)) return false;
  let fn = BigInt(index);
  const size = BigInt(treeSize);
  if (fn < 0n || fn >= size) return false;
  let sn = size - 1n;
  let r = leafHash(leaf);
  for (const p of proof) {
    if (p.length !== 32) return false;
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(r, expectedRoot);
}

/** RFC 9162 section 2.1.4.2. As in RFC 9162, every tree is consistent with the empty tree (first = 0). */
export function verifyConsistency(
  first: number,
  second: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  proof: readonly Uint8Array[],
): boolean {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second)) return false;
  if (first < 0 || second < 0 || first > second) return false;
  if (first === second) return proof.length === 0 && equal(firstRoot, secondRoot);
  if (first === 0) return proof.length === 0;
  if (proof.length === 0 || proof.some((c) => c.length !== 32)) return false;
  let path = [...proof];
  const f = BigInt(first);
  if ((f & (f - 1n)) === 0n) path = [firstRoot, ...path];
  let fn = f - 1n;
  let sn = BigInt(second) - 1n;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return equal(fr, firstRoot) && equal(sr, secondRoot) && sn === 0n;
}

/** Root from the VCP v1.2 section 6.2.1 example code (odd node duplicated). Not RFC 6962. */
export function legacyExampleRoot(leaves: readonly Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error("the section 6.2.1 example code has no empty-tree root");
  let level = leaves.map(leafHash);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i]!, level[i + 1] ?? level[i]!));
    level = next;
  }
  return level[0]!;
}
