/** UUIDv7 and VCP dual-format timestamps. TimestampInt is nanoseconds as bigint. */

import { toHex } from "./bytes.js";

export const PRECISION_DIGITS: Record<string, number> = { MILLISECOND: 3, MICROSECOND: 6, NANOSECOND: 9 };

export function uuid7(unixMs?: number, rand?: Uint8Array): string {
  const ms = unixMs ?? Date.now();
  if (!Number.isSafeInteger(ms) || ms < 0 || ms >= 2 ** 48) throw new RangeError("unixMs out of range");
  const r = rand ?? globalThis.crypto.getRandomValues(new Uint8Array(10));
  if (r.length !== 10) throw new Error("rand must be 10 bytes");
  const b = new Uint8Array(16);
  let t = BigInt(ms);
  for (let i = 5; i >= 0; i--) {
    b[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  b.set(r, 6);
  b[6] = 0x70 | (b[6]! & 0x0f);
  b[8] = 0x80 | (b[8]! & 0x3f);
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Current time in nanoseconds. Resolution is one millisecond (Date.now()); the sub-millisecond digits are zero. */
export function nowNs(): bigint {
  return BigInt(Date.now()) * 1_000_000n;
}

const pad = (n: number, w: number): string => String(n).padStart(w, "0");

export function isoFromNs(ns: bigint, precision = "MILLISECOND"): string {
  const digits = Object.prototype.hasOwnProperty.call(PRECISION_DIGITS, precision) ? PRECISION_DIGITS[precision] : undefined;
  if (digits === undefined) throw new Error(`unknown precision ${precision}`);
  if (ns < 0n) throw new RangeError("negative timestamp");
  const seconds = ns / 1_000_000_000n;
  const frac = ns % 1_000_000_000n;
  const d = new Date(Number(seconds) * 1000);
  const base =
    `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}:${pad(d.getUTCMinutes(), 2)}:${pad(d.getUTCSeconds(), 2)}`;
  return `${base}.${frac.toString().padStart(9, "0").slice(0, digits)}Z`;
}

const ISO = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/;

function daysInMonth(y: number, m: number): number {
  return [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]!;
}

/** Days from 1970-01-01 to the given proleptic Gregorian date (y >= 1). */
function daysFromCivil(y: number, m: number, d: number): bigint {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return BigInt(era * 146097 + doe - 719468);
}

/**
 * Parse RFC 3339 (the same rules as the Python package: years 0001-9999, no
 * leap second, offsets up to 23:59); returns [nanoseconds, fractional digits given].
 */
export function nsFromIso(value: string): [bigint, number] {
  const m = typeof value === "string" ? ISO.exec(value) : null;
  if (!m) throw new Error(`not an RFC 3339 timestamp: ${JSON.stringify(value)}`);
  const [, ys, mos, ds, hs, mis, ss, frac = "", tz] = m;
  const y = +ys!, mo = +mos!, d = +ds!, hh = +hs!, mm = +mis!, sec = +ss!;
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo) || hh > 23 || mm > 59 || sec > 59) {
    throw new Error(`invalid date or time: ${JSON.stringify(value)}`);
  }
  let seconds = daysFromCivil(y, mo, d) * 86400n + BigInt(hh * 3600 + mm * 60 + sec);
  if (tz !== "Z") {
    const oh = +tz!.slice(1, 3), om = +tz!.slice(4, 6);
    if (oh > 23 || om > 59) throw new Error(`invalid UTC offset: ${tz}`);
    seconds -= (tz![0] === "+" ? 1n : -1n) * BigInt(oh * 3600 + om * 60);
  }
  const fracNs = frac ? BigInt(frac.padEnd(9, "0")) : 0n;
  return [seconds * 1_000_000_000n + fracNs, frac.length];
}

function floorDiv(a: bigint, b: bigint): bigint {
  const q = a / b;
  return (a % b !== 0n && (a < 0n) !== (b < 0n)) ? q - 1n : q;
}

export function isoMatchesNs(iso: string, ns: bigint): boolean {
  const [isoNs, digits] = nsFromIso(iso);
  const unit = 10n ** BigInt(9 - digits);
  return floorDiv(ns, unit) === floorDiv(isoNs, unit);
}
