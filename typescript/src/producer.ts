/**
 * Producing VCP v1.2 events, batches and AnchorRecords. Nothing is sent
 * anywhere: external anchoring is the caller's job (VCP v1.2 section 6.3.3
 * requires it at every tier).
 */

import { MerkleTree } from "./merkle.js";
import { computeEventHash, formatEventHash, parseHash } from "./hashing.js";
import { SigningKey, signEventHash, signMerkleRoot } from "./signing.js";
import { isoFromNs, nowNs, uuid7 } from "./timeutil.js";
import { fromHex, toHex } from "./bytes.js";

export type VcpEvent = {
  Header: Record<string, unknown>;
  Payload: Record<string, unknown>;
  Security: Record<string, unknown>;
  [k: string]: unknown;
};

export const SECURITY_VERSION = "1.1";

function clone<T>(v: T): T {
  return structuredClone(v);
}

export function sealEvent(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: SigningKey,
  opts: { prevHash?: string | null; hashAlgo?: string } = {},
): VcpEvent {
  const algo = opts.hashAlgo ?? "SHA256";
  const h = computeEventHash(header, payload, { prevHash: opts.prevHash ?? null, algo });
  const security: Record<string, unknown> = {
    Version: SECURITY_VERSION,
    EventHash: formatEventHash(h, algo),
    HashAlgo: algo,
    Signature: signEventHash(h, key),
    SignAlgo: "ED25519",
  };
  if (opts.prevHash != null) security.PrevHash = formatEventHash(opts.prevHash, algo);
  return { Header: clone(header), Payload: clone(payload), Security: security };
}

export interface Batch {
  events: VcpEvent[];
  merkleRoot: string;
  tree: MerkleTree;
  inclusionProof(index: number): string[];
}

export function buildBatch(events: readonly VcpEvent[], anchorReference?: string): Batch {
  if (events.length === 0) throw new Error("a batch needs at least one event");
  const out = events.map(clone);
  const tree = new MerkleTree(out.map((e) => fromHex(parseHash(e.Security.EventHash))));
  const root = toHex(tree.root);
  const ref = anchorReference ?? root;
  out.forEach((e, i) => {
    e.Security.MerkleRoot = root;
    e.Security.MerkleIndex = i;
    e.Security.AnchorReference = ref;
  });
  return { events: out, merkleRoot: root, tree, inclusionProof: (i) => tree.inclusionProof(i).map(toHex) };
}

/** AnchorRecord (section 6.3.3). The signature covers the Merkle root only (section 6.3.1). */
export function anchorRecord(
  batch: Batch,
  key: SigningKey,
  policyId: string,
  anchorTarget?: Record<string, unknown>,
  timestampNs?: bigint,
): Record<string, unknown> {
  const rec: Record<string, unknown> = {
    MerkleRoot: batch.merkleRoot,
    Signature: signMerkleRoot(batch.merkleRoot, key),
    SignAlgo: "ED25519",
    Timestamp: timestampNs ?? nowNs(),
    EventCount: batch.events.length,
    FirstEventID: batch.events[0]!.Header.EventID,
    LastEventID: batch.events[batch.events.length - 1]!.Header.EventID,
    PolicyID: policyId,
  };
  if (anchorTarget) rec.AnchorTarget = { ...anchorTarget };
  return rec;
}

export interface ProducerOptions {
  precision?: string;
  usePrevHash?: boolean;
  hashAlgo?: string;
  startSequence?: number;
  prevHash?: string | null;
}

export class Producer {
  private sequence: number;
  private lastHash: string | null;
  private pending: VcpEvent[] = [];
  readonly precision: string;
  readonly usePrevHash: boolean;
  readonly hashAlgo: string;

  constructor(
    readonly key: SigningKey,
    readonly actorId: string,
    readonly chainId: string,
    readonly policyId: string,
    opts: ProducerOptions = {},
  ) {
    this.precision = opts.precision ?? "MILLISECOND";
    this.usePrevHash = opts.usePrevHash ?? false;
    this.hashAlgo = opts.hashAlgo ?? "SHA256";
    this.sequence = opts.startSequence ?? 0;
    this.lastHash = opts.prevHash ?? null;
  }

  create(
    eventType: string,
    payload: Record<string, unknown>,
    opts: { timestampNs?: bigint; eventId?: string; traceId?: string } = {},
  ): VcpEvent {
    const ts = opts.timestampNs ?? nowNs();
    const header: Record<string, unknown> = {
      EventID: opts.eventId ?? uuid7(Number(ts / 1_000_000n)),
      TimestampISO: isoFromNs(ts, this.precision),
      TimestampInt: ts,
      EventType: eventType,
      ActorID: this.actorId,
      ChainID: this.chainId,
      SequenceNum: this.sequence,
      PolicyID: this.policyId,
    };
    if (opts.traceId !== undefined) header.TraceID = opts.traceId;
    const ev = sealEvent(header, payload, this.key, {
      prevHash: this.usePrevHash ? this.lastHash : null,
      hashAlgo: this.hashAlgo,
    });
    this.sequence += 1;
    this.lastHash = parseHash(ev.Security.EventHash);
    this.pending.push(ev);
    return ev;
  }

  closeBatch(opts: { anchorTarget?: Record<string, unknown>; anchorReference?: string; timestampNs?: bigint } = {}): {
    batch: Batch;
    record: Record<string, unknown>;
  } {
    const batch = buildBatch(this.pending, opts.anchorReference);
    const record = anchorRecord(batch, this.key, this.policyId, opts.anchorTarget, opts.timestampNs);
    this.pending = [];
    return { batch, record };
  }
}
