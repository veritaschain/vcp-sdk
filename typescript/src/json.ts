/**
 * Strict JSON parsing for verification input.
 *
 * `JSON.parse` turns every number into a binary64 value, so a VCP
 * `TimestampInt` such as 1791504000123456789 silently becomes
 * 1791504000123456768. This parser returns a `bigint` for any integer literal
 * outside the safe range (|n| > 2^53 - 1), so the exact value reaches the
 * canonicaliser. It also rejects duplicate keys, a byte-order mark, non-JSON
 * constants, numbers outside binary64 range, nesting deeper than 128 levels and
 * integer literals longer than 4300 digits (the same limits as the Python
 * package).
 *
 * JSON Lines are split on "\n" only (a trailing "\r" is removed).
 */

export const MAX_DEPTH = 128;
export const MAX_INT_DIGITS = 4300;

export class StrictJSONError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictJSONError";
  }
}

export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  fail(msg: string): never {
    throw new StrictJSONError(`${msg} at offset ${this.i}`);
  }

  ws(): void {
    while (this.i < this.s.length && WS.has(this.s.charCodeAt(this.i))) this.i++;
  }

  private depth = 0;

  parseDocument(): JsonValue {
    if (this.s.charCodeAt(0) === 0xfeff) this.fail("byte-order mark");
    this.ws();
    const v = this.value();
    this.ws();
    if (this.i !== this.s.length) this.fail("trailing characters");
    return v;
  }

  value(): JsonValue {
    const c = this.s[this.i];
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    if (c === "t") return this.literal("true", true);
    if (c === "f") return this.literal("false", false);
    if (c === "n") return this.literal("null", null);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.number();
    return this.fail("unexpected character");
  }

  literal<T extends JsonValue>(word: string, v: T): T {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    return this.fail("invalid literal");
  }

  enter(): void {
    if (this.depth >= MAX_DEPTH) this.fail(`nesting deeper than ${MAX_DEPTH} levels`);
    this.depth++;
  }

  object(): { [key: string]: JsonValue } {
    this.enter();
    this.i++;
    const out: { [key: string]: JsonValue } = Object.create(null);
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      this.depth--;
      return {};
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail("expected string key");
      const k = this.string();
      if (seen.has(k)) this.fail(`duplicate key ${JSON.stringify(k)}`);
      seen.add(k);
      this.ws();
      if (this.s[this.i] !== ":") this.fail("expected ':'");
      this.i++;
      this.ws();
      out[k] = this.value();
      this.ws();
      const c = this.s[this.i++];
      if (c === "}") break;
      if (c !== ",") this.fail("expected ',' or '}'");
    }
    const plain: { [key: string]: JsonValue } = {};
    for (const k of Object.keys(out)) {
      Object.defineProperty(plain, k, { value: out[k], enumerable: true, writable: true, configurable: true });
    }
    this.depth--;
    return plain;
  }

  array(): JsonValue[] {
    this.enter();
    this.i++;
    const out: JsonValue[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      this.ws();
      const c = this.s[this.i++];
      if (c === "]") break;
      if (c !== ",") this.fail("expected ',' or ']'");
    }
    this.depth--;
    return out;
  }

  string(): string {
    this.i++;
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) this.fail("unterminated string");
      const code = this.s.charCodeAt(this.i);
      if (code === 0x22) {
        this.i++;
        return out;
      }
      if (code < 0x20) this.fail("control character in string");
      if (code === 0x5c) {
        const e = this.s[this.i + 1];
        this.i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default:
            this.fail("bad escape");
        }
        continue;
      }
      out += this.s[this.i];
      this.i++;
    }
  }

  number(): number | bigint {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i));
    if (!m) return this.fail("bad number");
    const text = m[0];
    this.i += text.length;
    if (m[2] === undefined && m[3] === undefined) {
      if (text.replace("-", "").length > MAX_INT_DIGITS) this.fail(`integer literal longer than ${MAX_INT_DIGITS} digits`);
      const b = BigInt(text);
      if (b > BigInt(Number.MAX_SAFE_INTEGER) || b < -BigInt(Number.MAX_SAFE_INTEGER)) return b;
      return Number(text);
    }
    const x = Number(text);
    if (!Number.isFinite(x)) this.fail("number out of binary64 range");
    return x;
  }
}

/** Parse JSON text strictly. Large integers come back as `bigint`. */
export function parseJson(text: string | Uint8Array): JsonValue {
  const s = typeof text === "string" ? text : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(text);
  return new Parser(s).parseDocument();
}

/** Parse one JSON value per non-empty line (lines end with "\n"). */
export function parseJsonLines(text: string | Uint8Array): JsonValue[] {
  const s = typeof text === "string" ? text : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(text);
  const out: JsonValue[] = [];
  for (let line of s.split("\n")) {
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line.replace(/[ \t]/g, "") !== "") out.push(parseJson(line));
  }
  return out;
}
