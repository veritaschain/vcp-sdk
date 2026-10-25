// Produce a batch with the TypeScript SDK: writes <dir>/ts-events.jsonl and <dir>/ts-anchor.json.
import { writeFileSync } from "node:fs";
import * as vcp from "../../typescript/dist/index.js";

const dir = process.argv[2];
const key = new vcp.SigningKey(process.argv[3]);
const p = new vcp.Producer(key, "ts-producer", "chain-x", "org.veritaschain.sdk:crosslang", { precision: "NANOSECOND", usePrevHash: true });
for (let i = 0; i < 13; i++) {
  p.create(i ? "ORD" : "INIT", { "VCP-TRADE": { Symbol: "USDJPY", Price: `151.${String(i).padStart(3, "0")}`, Note: "跨言語 \u0007 \u2028 test" } }, { timestampNs: 1791504000123456768n + BigInt(i) * 256_000n }); // multiples of 256: exactly representable in binary64
}
const { batch, record } = p.closeBatch({ anchorTarget: { Type: "PUBLIC_SERVICE", Identifier: "example.invalid", Proof: "synthetic" }, timestampNs: 1791504999000000000n });
writeFileSync(`${dir}/ts-events.jsonl`, batch.events.map((e) => vcp.toJson(e)).join("\n") + "\n");
writeFileSync(`${dir}/ts-anchor.json`, vcp.toJson(record) + "\n");
