// Verify a batch with the TypeScript SDK. Prints the status; exit 0 if it equals argv[5].
import { readFileSync } from "node:fs";
import * as vcp from "../../typescript/dist/index.js";

const [events, anchor, pub, expected] = process.argv.slice(2);
const rep = vcp.verifyBatch(vcp.parseJsonLines(readFileSync(events, "utf8")), vcp.parseJson(readFileSync(anchor, "utf8")), { publicKey: pub, externalAnchorVerifier: () => true });
const chain = vcp.verifyChain(vcp.parseJsonLines(readFileSync(events, "utf8")));
console.log(JSON.stringify({ batch: rep.status, chain: chain.status, non_valid: rep.checks.filter((c) => c.status !== "VALID") }));
process.exit(rep.status === expected && chain.status === "VALID" ? 0 : 1);
