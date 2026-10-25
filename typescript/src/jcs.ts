/**
 * Canonical JSON for EventHash: RFC 8785 (JCS) with one rule for integers
 * (INTERPRETATIONS.md, I-4), identical to the Python package:
 *
 * - a `bigint` is written as its exact decimal digits;
 * - a `number` is written as RFC 8785 writes it (`Number#toString`), except that
 *   an integral number of magnitude in [2^53, 1e21) is rejected, because its
 *   RFC 8785 form is a plain digit string that could equal the digits of a
 *   different integer.
 *
 * The parser in json.ts returns `bigint` for integer literals outside the safe
 * range, so with these rules different numeric values never share a canonical
 * form. `strict: true` applies RFC 8785 to bigints as well: a bigint that
 * binary64 cannot represent exactly is rejected, others are written in RFC 8785
 * form.
 */

import type { JsonValue } from "./json.js";
import { MAX_DEPTH } from "./json.js";

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

export interface CanonicalizeOptions {
  strict?: boolean;
}

const TWO53 = 2 ** 53;

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw new CanonicalizationError("string contains a lone surrogate");
      out += s[i]! + s[i + 1]!;
      i++;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) throw new CanonicalizationError("string contains a lone surrogate");
    switch (c) {
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0a: out += "\\n"; break;
      case 0x0c: out += "\\f"; break;
      case 0x0d: out += "\\r"; break;
      case 0x22: out += '\\"'; break;
      case 0x5c: out += "\\\\"; break;
      default:
        out += c < 0x20 ? "\\u" + c.toString(16).padStart(4, "0") : s[i]!;
    }
  }
  return out + '"';
}

function esNumber(v: number): string {
  return Object.is(v, -0) ? "0" : String(v);
}

export function formatNumber(v: number | bigint, opts: CanonicalizeOptions = {}): string {
  if (typeof v === "bigint") {
    if (!opts.strict) return v.toString();
    const f = Number(v);
    if (Number.isFinite(f) && BigInt(f) === v) return esNumber(f);
    throw new CanonicalizationError(`integer ${v} is not exactly representable as binary64; RFC 8785 processing would change the value`);
  }
  if (!Number.isFinite(v)) throw new CanonicalizationError("NaN and Infinity are not valid JSON numbers");
  if (!opts.strict && Number.isInteger(v) && Math.abs(v) >= TWO53 && Math.abs(v) < 1e21) {
    throw new CanonicalizationError(
      "a floating-point number with an integral value of 2**53 or more is ambiguous; write it as an integer (bigint) or a decimal string",
    );
  }
  return esNumber(v);
}

function serialize(v: unknown, opts: CanonicalizeOptions, out: string[], depth: number): void {
  if (v === null) out.push("null");
  else if (v === true) out.push("true");
  else if (v === false) out.push("false");
  else if (typeof v === "string") out.push(serializeString(v));
  else if (typeof v === "number" || typeof v === "bigint") out.push(formatNumber(v, opts));
  else if (typeof v === "object") {
    if (depth >= MAX_DEPTH) throw new CanonicalizationError(`nesting deeper than ${MAX_DEPTH} levels`);
    if (Array.isArray(v)) {
      out.push("[");
      v.forEach((item, i) => {
        if (i) out.push(",");
        serialize(item, opts, out, depth + 1);
      });
      out.push("]");
      return;
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new CanonicalizationError("only plain objects can be canonicalised");
    const obj = v as Record<string, unknown>;
    // Default sort compares UTF-16 code units, as RFC 8785 section 3.2.3 requires.
    const keys = Object.keys(obj).sort();
    out.push("{");
    keys.forEach((k, i) => {
      if (i) out.push(",");
      out.push(serializeString(k), ":");
      serialize(obj[k], opts, out, depth + 1);
    });
    out.push("}");
  } else {
    throw new CanonicalizationError(`unsupported type: ${typeof v}`);
  }
}

/** Canonical form as a string. */
export function canonicalizeString(value: JsonValue | unknown, opts: CanonicalizeOptions = {}): string {
  const out: string[] = [];
  serialize(value, opts, out, 0);
  return out.join("");
}

/** Canonical form as UTF-8 bytes. */
export function canonicalize(value: JsonValue | unknown, opts: CanonicalizeOptions = {}): Uint8Array {
  return new TextEncoder().encode(canonicalizeString(value, opts));
}

/** True if the value holds a bigint whose form here differs from strict RFC 8785. Iterative. */
export function differsFromRfc8785(value: unknown): boolean {
  const stack: unknown[] = [value];
  while (stack.length) {
    const v = stack.pop();
    if (typeof v === "bigint") {
      if (v > BigInt(TWO53) || v < -BigInt(TWO53)) {
        try {
          if (formatNumber(v, { strict: true }) !== v.toString()) return true;
        } catch {
          return true;
        }
      }
    } else if (Array.isArray(v)) stack.push(...v);
    else if (v !== null && typeof v === "object") stack.push(...Object.values(v as object));
  }
  return false;
}
