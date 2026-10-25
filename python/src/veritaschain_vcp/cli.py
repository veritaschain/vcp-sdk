"""Command line: ``vcp`` (or ``python -m veritaschain_vcp``).

Exit codes: 0 VALID (or success), 1 INVALID, 2 INDETERMINATE, 3 usage, input
or internal error. A crash never exits with 1.

Private keys are read only from a file (``--private-key-file``, ``-`` for
stdin) or the ``VCP_PRIVATE_KEY`` environment variable, never from a command
line argument. On POSIX systems a key file readable by group or others is
refused. ``vcp keygen --out FILE`` writes a new seed with mode 0600.

The ``seal`` command is the signing side of the MQL5 integration: an Expert
Advisor writes unsigned events (Header, Payload and the EventHash it computed,
one JSON object per line); this command checks each line, adds the signature,
builds the batch and writes the AnchorRecord. It signs whatever valid events
the input file contains, so protect the folder the EA writes to.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .hashing import compute_event_hash, format_event_hash, parse_hash
from .jsonio import StrictJSONError, load_jsonl, loads
from .producer import anchor_record, build_batch, seal_event
from .signing import SigningKey, generate_key
from .verify import INDETERMINATE, INVALID, VALID, precheck_unsigned, verify_batch, verify_chain, verify_event

_EXIT = {VALID: 0, INVALID: 1, INDETERMINATE: 2}


def _read(path: str) -> bytes:
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()


def _events(path: str) -> list[Any]:
    data = _read(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("input is not valid UTF-8") from exc
    stripped = text.lstrip()
    if stripped.startswith("["):
        v = loads(text)
        if not isinstance(v, list):
            raise StrictJSONError("expected a JSON array of events")
        return v
    return load_jsonl(text)


def _key_text(args: argparse.Namespace, attr: str) -> str | None:
    """A public key given literally or as a file path."""
    v = getattr(args, attr, None)
    if v is None:
        return None
    p = Path(v)
    return p.read_text().strip() if p.is_file() else v


class UsageError(Exception):
    pass


def _private_key(args: argparse.Namespace) -> SigningKey:
    path = getattr(args, "private_key_file", None)
    if path == "-":
        return SigningKey(sys.stdin.readline().strip())
    if path:
        if os.name == "posix":
            mode = os.stat(path).st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise UsageError(f"{path} is readable by group or others; run: chmod 600 {path}")
        return SigningKey(Path(path).read_text().strip())
    env = os.environ.get("VCP_PRIVATE_KEY")
    if env:
        return SigningKey(env.strip())
    raise UsageError("no private key: use --private-key-file FILE (or -) or set VCP_PRIVATE_KEY")


def _emit(report: Any) -> int:
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    return _EXIT[report.status]


def cmd_keygen(args: argparse.Namespace) -> int:
    k = generate_key()
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(k.seed_base64() + "\n")
    print(json.dumps({"private_key_file": args.out, "public_key_base64": k.verify_key.to_base64()}, indent=2))
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    ev = loads(_read(args.event))
    sec = ev.get("Security", {}) if isinstance(ev, dict) else {}
    h = compute_event_hash(ev["Header"], ev["Payload"], prev_hash=sec.get("PrevHash"), algo=args.algo)
    print(format_event_hash(h, args.algo) if args.prefixed else h)
    return 0


def cmd_verify_event(args: argparse.Namespace) -> int:
    return _emit(verify_event(loads(_read(args.event)), _key_text(args, "public_key")))


def cmd_verify_batch(args: argparse.Namespace) -> int:
    events = _events(args.events)
    record = loads(_read(args.anchor)) if args.anchor else None
    if isinstance(record, dict) and "AnchorRecord" in record and len(record) == 1:
        record = record["AnchorRecord"]
    return _emit(verify_batch(events, record, _key_text(args, "public_key"), _key_text(args, "anchor_public_key")))


def cmd_verify_chain(args: argparse.Namespace) -> int:
    return _emit(verify_chain(_events(args.events), prior_hash=args.prior_hash))


def cmd_seal(args: argparse.Namespace) -> int:
    key = _private_key(args)
    unsigned = _events(args.events)
    if not unsigned:
        raise UsageError("no events in the input")
    sealed = []
    prev: str | None = None
    if args.prior_hash is not None:
        try:
            prev = parse_hash(args.prior_hash)
        except ValueError:
            raise UsageError("--prior-hash is not a 32-byte hex digest") from None
    for n, ev in enumerate(unsigned, 1):
        problem = precheck_unsigned(ev)
        if problem:
            print(f"line {n}: {problem}; refusing to sign", file=sys.stderr)
            return 3
        given = ev.get("Security", {}) if isinstance(ev.get("Security"), dict) else {}
        if "EventHash" not in given and not args.allow_missing_hash:
            print(f"line {n}: no producer-written Security.EventHash (use --allow-missing-hash to sign anyway)", file=sys.stderr)
            return 3
        link = given.get("PrevHash")
        if link is None and args.prev_hash:
            link = prev
        if n == 1 and args.prior_hash is not None and link is None:
            print("line 1: no PrevHash, but --prior-hash was given", file=sys.stderr)
            return 3
        if n == 1 and args.prior_hash is None and given.get("PrevHash") is not None:
            print("warning: line 1 links to an earlier event (PrevHash) that is not checked; "
                  "pass --prior-hash with the previous file's last_event_hash to check it", file=sys.stderr)
        if link is not None and prev is not None and parse_hash(link) != parse_hash(prev):
            print(f"line {n}: PrevHash does not match the previous event", file=sys.stderr)
            return 3
        e = seal_event(ev["Header"], ev["Payload"], key, prev_hash=link)
        if "EventHash" in given and parse_hash(given["EventHash"]) != parse_hash(e["Security"]["EventHash"]):
            print(f"line {n}: the EventHash written by the producer differs from the recomputed one; refusing to sign", file=sys.stderr)
            return 3
        sealed.append(e)
        prev = e["Security"]["EventHash"]
    batch = build_batch(sealed, anchor_reference=args.anchor_reference)
    policy = args.policy_id or sealed[0]["Header"]["PolicyID"]
    record = anchor_record(batch, key, policy)
    out = Path(args.out)
    out.write_text("".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in batch.events), encoding="utf-8")
    Path(args.anchor_out).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    last = batch.events[-1]
    print(json.dumps({"events": len(batch.events), "merkle_root": batch.merkle_root,
                      "last_sequence": last["Header"]["SequenceNum"],
                      "last_event_hash": parse_hash(last["Security"]["EventHash"]),
                      "note": "AnchorTarget not set: submit merkle_root to an external anchor and add the proof"}, indent=2))
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse would exit 2, which means INDETERMINATE here
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(3)


def main(argv: list[str] | None = None) -> int:
    ap = _Parser(prog="vcp", description="VCP v1.2 offline core (veritaschain-vcp %s)" % __version__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    p = sub.add_parser("keygen", help="generate an Ed25519 key pair; writes the seed to --out with mode 0600")
    p.add_argument("--out", required=True, help="file for the private key seed (must not exist)")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("hash", help="compute the EventHash of an event")
    p.add_argument("event")
    p.add_argument("--algo", default="SHA256", choices=["SHA256", "SHA3_256", "BLAKE3"])
    p.add_argument("--prefixed", action="store_true", help="print the sha256: form")
    p.set_defaults(fn=cmd_hash)

    p = sub.add_parser("verify-event", help="verify one event")
    p.add_argument("event")
    p.add_argument("--public-key", help="trusted Ed25519 public key (base64/hex, or a file)")
    p.set_defaults(fn=cmd_verify_event)

    p = sub.add_parser("verify-batch", help="verify a batch against its AnchorRecord")
    p.add_argument("events", help="JSON array or JSON Lines, in Merkle order")
    p.add_argument("--anchor", help="AnchorRecord JSON")
    p.add_argument("--public-key")
    p.add_argument("--anchor-public-key")
    p.set_defaults(fn=cmd_verify_batch)

    p = sub.add_parser("verify-chain", help="check SequenceNum and PrevHash links")
    p.add_argument("events")
    p.add_argument("--prior-hash")
    p.set_defaults(fn=cmd_verify_chain)

    p = sub.add_parser("seal", help="sign unsigned events and build a batch (MQL5 sidecar)")
    p.add_argument("events")
    p.add_argument("--private-key-file", help="file holding the Ed25519 seed (base64 or hex), or - for stdin; "
                   "otherwise VCP_PRIVATE_KEY is used")
    p.add_argument("--allow-missing-hash", action="store_true",
                   help="sign lines that carry no producer-written EventHash")
    p.add_argument("--out", required=True)
    p.add_argument("--anchor-out", required=True)
    p.add_argument("--policy-id")
    p.add_argument("--anchor-reference")
    p.add_argument("--prev-hash", action="store_true", help="link events with PrevHash")
    p.add_argument("--prior-hash", help="EventHash of the event before line 1 (the previous file's last_event_hash); "
                   "line 1 must link to it")
    p.set_defaults(fn=cmd_seal)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Exception as exc:  # noqa: BLE001 - exit 1 is reserved for INVALID
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
