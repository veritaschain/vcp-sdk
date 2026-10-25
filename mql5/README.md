# MQL5: VCP.mqh

`Include/VeritasChain/VCP.mqh` lets an Expert Advisor record VCP v1.2 events
inside MetaTrader 5. It builds Header/Payload objects, serialises them in the
SDK's canonical form (RFC 8785, with integers as exact digits: INTERPRETATIONS.md
I-4), computes the SHA-256 EventHash, and writes unsigned events as JSON Lines.
It also computes RFC 6962 Merkle roots and verifies inclusion proofs.

**Not compiled in this repository's CI.** Before use, compile and run
`Scripts/VeritasChain/VCP_SelfTest.mq5` (generated from `test-vectors/vectors.json`
by `tools/gen_mql5_selftest.py`). It checks canonical output for the vector
objects (including large integers), EventHashes, Merkle roots for 1–24 leaves,
inclusion proofs, and the writer: line format, resume after reopening (also when
the Payload contains `EventHash` keys), refusal of another chain and of an
incomplete last line, and continuing a chain in a new file. It prints
`N passed, 0 failed` to the Experts log when all of them match the
Python/TypeScript results. It does not cover every error path.

## Why signing happens outside the terminal

MQL5 has no Ed25519. The EA writes each event with the EventHash it computed,
and a sidecar process signs them, builds the batch and writes the AnchorRecord.
The private key stays with the sidecar, not in the terminal. VCP v1.2
section 2.1 lists "Ed25519 (Delegated)" for the Silver tier without defining
it; treating this sidecar arrangement as that is the SDK's reading.

## Use

```mql5
#include <VeritasChain/VCP.mqh>
CVcpWriter writer;

int OnInit()
  {
   //--- one file holds one ActorID/ChainID
   if(!writer.Open("vcp-my-ea-12345-20261025.jsonl", "my-ea", "my-ea-12345", "org.example:silver-mt5", 3, true))
     {
      Print("VCP: ", VcpLastError());
      return INIT_FAILED;
     }
   if(writer.NextSequence() == 0)
     {
      CVcpJson *p = VcpObj();
      CVcpJson *gov = VcpObj();
      gov.Put("AlgoID", VcpStr("my-ea"));
      p.Put("VCP-GOV", gov);
      writer.Write("INIT", p);         // takes ownership of p; returns "" on failure
     }
   return INIT_SUCCEEDED;
  }
```

`Open(file, actor, chain, policy, digits, usePrevHash, startSequence = 0, prevHash = "")`:

* If the file already holds events, the writer continues from its last line
  (SequenceNum + 1, and that line's EventHash as the next PrevHash);
  `startSequence` and `prevHash` are ignored.
* If the file is new or empty, the chain starts at `startSequence`, linked to
  `prevHash`. Pass the previous file's last SequenceNum + 1 and EventHash to
  continue a chain in a new file; `VcpFindPrevious` finds them in the newest
  earlier file named `<prefix>YYYYMMDD<suffix>`.
* `Open` returns false, sets `VcpLastError()` and leaves the file as it is when
  the last line is incomplete (the file does not end with a newline, for example
  after a crash during a write) or is not an event of this ActorID and ChainID.
  Remove the partial line, or use another file, and open again.

`Write` returns the EventHash, or `""` with `VcpLastError()` set; on failure
neither SequenceNum nor the chain advances. After a short write (fewer bytes
written than the line has) the writer refuses further writes, because the file
may now end with a partial line. `LastHash()` returns the EventHash of the last
event written or resumed.

## The example EA and the daily workflow

`Experts/VeritasChain/VCP_ExampleEA.mq5` records the order and deal
transactions of one magic number (it does not trade): ORD when an order is
placed (looked up in the open orders, or in the history if a market order has
already left them), EXE for each deal, CXL when an order is cancelled or expires,
and ERR_REJECT when it is rejected (with `VCP-TRADE.RejectReason` and
`VCP-TRADE.ErrorDetails`; see INTERPRETATIONS.md I-7 for why ErrorDetails sits
inside the module). Prices and volumes are written as decimal
strings, as VCP v1.2 section 4.2.2 requires; the builder has no floating-point
type.

It writes one file per UTC day, `MQL5/Files/vcp-<ChainID>-<YYYYMMDD>.jsonl`, where
ChainID is `<ActorID>-<account>-<magic>` (characters other than letters, digits,
`.`, `_` and `-` become `_` in the file name). A new day's file continues the
SequenceNum and PrevHash chain from the previous file. Each closed file is one
batch, which matches the 24-hour anchoring interval VCP v1.2 section 2.1 gives
for Silver.

Seal each closed file (not today's, which the EA is still writing):

```bash
pip install "git+https://github.com/veritaschain/vcp-sdk.git@v0.1.0#subdirectory=python"
vcp keygen --out /secure/path/ea.key          # once; prints the public key
F="<MT5 data folder>/MQL5/Files/vcp-mt5-example-ea-12345-70010"   # account 12345, magic 70010
vcp seal "$F-20261024.jsonl" --private-key-file /secure/path/ea.key \
    --prior-hash <last_event_hash from sealing 20261023> \
    --out sealed-20261024.jsonl --anchor-out anchor-20261024.json
```

Before signing, `vcp seal` checks every line: structure, TimestampISO against
TimestampInt, that the EventHash the EA wrote equals the recomputed one, and that
each PrevHash links to the previous line (and line 1 to `--prior-hash`). If any
line fails it signs nothing. It prints `last_event_hash` and `last_sequence` for
the next day's `--prior-hash`. Omit `--prior-hash` for the first file of a chain,
and when the EA runs with `InpPrevHash = false` (then no line carries a PrevHash
and there is no link between files to check). Without `--prior-hash`, a line 1
that does carry a PrevHash is signed with a warning that its link was not checked.
`vcp seal` signs every valid line in the file, so protect `MQL5/Files` from other
writers. Then anchor `merkle_root` externally (VCP v1.2 section 6.3.3) and add the
proof to `AnchorTarget` in the AnchorRecord. To check a day's file against the
previous one later: `vcp verify-chain sealed-20261024.jsonl --prior-hash <hash>`.

On Windows the key file's permissions are not checked by `vcp`; restrict its ACL
to the account that runs the sidecar.

## Limits

* Time: `VcpNowNs()` aligns `GetMicrosecondCount()` to `TimeGMT()` at a second
  boundary (the first call waits up to about one second). If the two drift apart
  by more than two seconds it re-bases to the current whole `TimeGMT()` second
  without waiting, so the value can jump by up to about a second. It never
  returns a value earlier than the previous one: after a backwards re-base it
  holds until the clock catches up. Accuracy is best-effort (ClockSyncStatus
  `BEST_EFFORT`). In the Strategy Tester `TimeGMT()` is the simulated time, which
  follows the trade server's clock rather than UTC, so events produced there are
  labelled `Z` without being UTC.
* `VcpUuid7` draws its random bits from SHA-256 over time, a counter, the chart
  and account identifiers and `MathRand()`: unique in practice, not
  cryptographically random.
* The resume reads only the last line, and checks its Header prefix and Security
  object, not the whole line; `vcp seal` checks every line.
* No verifier beyond Merkle inclusion; verify batches with the Python or
  TypeScript package.
