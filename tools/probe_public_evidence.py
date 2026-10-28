#!/usr/bin/env python3
"""Bounded, read-only public demo probes; HTTP success is not evidence validity."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

PUBLIC_ORIGIN = "https://veritaschain-evidence-demo.kamimura0000.chatgpt.site"
AGENT = "VCP-Evidence-Probe/0.1 (+https://github.com/veritaschain/vcp-sdk)"
LIMIT = 256 * 1024
TIMEOUT = 15
ROOT = Path(__file__).resolve().parents[1]
HEADERS = ("content-type", "cache-control", "access-control-allow-origin",
           "access-control-allow-credentials", "server", "cf-ray")
CASES = {"intact": ("VALID", "INDETERMINATE"), "tampered": ("INVALID", "INVALID"),
         "missing-key": ("INDETERMINATE", "INDETERMINATE")}
NODE = r"""
const [url, agent, maximum, timeout] = process.argv.slice(1);
const limit = Number(maximum);
try {
  const response = await fetch(url, {redirect:'manual',
    headers:{Accept:'application/json', 'User-Agent':agent},
    signal:AbortSignal.timeout(Number(timeout)*1000)});
  const reader = response.body?.getReader();
  const chunks=[]; let size=0;
  if (reader) for (;;) {
    const {done,value}=await reader.read(); if(done) break;
    size+=value.byteLength;
    if(size>limit){await reader.cancel(); throw Error('Response exceeds byte limit');}
    chunks.push(Buffer.from(value));
  }
  const headers={};
  for(const name of ['content-type','cache-control','access-control-allow-origin',
      'access-control-allow-credentials','server','cf-ray']) {
    const value=response.headers.get(name); if(value!==null) headers[name]=value;
  }
  console.log(JSON.stringify({status:response.status,headers,
    body:Buffer.concat(chunks).toString('base64')}));
} catch(error) {console.error(String(error.message));process.exitCode=2;}
"""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("Non-finite JSON number: " + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def check_origin(value):
    url = urlsplit(value)
    if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("Use a bare approved origin without credentials")
    if value.rstrip("/") != PUBLIC_ORIGIN:
        if not (url.scheme == "http" and url.hostname == "127.0.0.1" and url.port):
            raise ValueError("Only the published HTTPS origin or explicit loopback HTTP is allowed")
    return value.rstrip("/")


def request(client, url, origin=None):
    """No redirects, retries, credentials, browser impersonation or unbounded reads."""
    if client == "python":
        headers = {"Accept": "application/json", "User-Agent": AGENT}
        if origin is not None:
            headers["Origin"] = origin
        try:
            response = build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=TIMEOUT)
        except HTTPError as error:
            response = error
        with response:
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError("Response exceeds byte limit")
            return response.code, {k: response.headers[k] for k in HEADERS if k in response.headers}, data
    if client == "node":
        import base64
        result = subprocess.run(["node", "--input-type=module", "-e", NODE, url, AGENT,
                                 str(LIMIT), str(TIMEOUT)], capture_output=True, timeout=TIMEOUT + 5)
        if result.returncode:
            raise ValueError("Node transport failed: " + result.stderr.decode("utf-8", "replace")[:300])
        value = strict_json(result.stdout)
        return value["status"], value["headers"], base64.b64decode(value["body"], validate=True)
    if client != "curl":
        raise ValueError("Unsupported HTTP client")
    with tempfile.TemporaryDirectory(prefix="vcp-http-") as temp:
        head, body = Path(temp) / "headers", Path(temp) / "body"
        result = subprocess.run([
            "curl", "--disable", "--silent", "--show-error", "--proto", "=https,http",
            "--max-time", str(TIMEOUT), "--max-filesize", str(LIMIT), "--max-redirs", "0",
            "--user-agent", AGENT, "--header", "Accept: application/json",
            "--dump-header", str(head), "--output", str(body), "--write-out", "%{http_code}", url
        ], capture_output=True, timeout=TIMEOUT + 5)
        if result.returncode:
            raise ValueError("curl transport failed: " + result.stderr.decode("utf-8", "replace")[:300])
        headers = {}
        for line in head.read_text(errors="replace").splitlines():
            key, sep, value = line.partition(":")
            if sep and key.lower() in HEADERS:
                headers[key.lower()] = value.strip()
        with body.open("rb") as handle:
            data = handle.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("Response exceeds byte limit")
        return int(result.stdout), headers, data


def validate(name, status, headers, data, bundle):
    if status != 200:
        code = re.search(rb"error code:\s*(\d+)", data[:1000], re.I)
        suffix = " / edge error " + code[1].decode() if code else ""
        raise ValueError("HTTP " + str(status) + suffix + "; not an evidence verdict")
    if headers.get("content-type", "").split(";")[0].lower().strip() != "application/json":
        raise ValueError("Expected application/json")
    if "no-store" not in headers.get("cache-control", "").lower():
        raise ValueError("Missing no-store cache policy")
    value = strict_json(data.decode("utf-8", "strict"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    if name == "health":
        if value.get("status") != "ok" or value.get("service") != "VCP evidence demonstration":
            raise ValueError("Health contract mismatch")
    elif name == "cases":
        items = value.get("cases")
        ids = [x.get("id") for x in items if isinstance(x, dict)] if isinstance(items, list) else []
        if value.get("format") != "vcp-evidence-demo/1" or len(ids) != 3 or set(ids) != set(CASES):
            raise ValueError("Case-directory contract mismatch")
        if value.get("sdk_version") != bundle["sdk_version"] or value.get("spec_version") != bundle["spec_version"]:
            raise ValueError("Case-directory version mismatch")
    else:
        if value.get("format") != "vcp-evidence-demo-verification/1" or value.get("case_id") != name:
            raise ValueError("Verification identity/format mismatch")
        if (value.get("local_status"), value.get("overall_status")) != CASES[name]:
            raise ValueError("Unexpected API-claimed outcomes; not yet locally verified")
        expected = next(x for x in bundle["cases"] if x["id"] == name)
        evidence = value.get("evidence", {})
        if not isinstance(evidence, dict) or any(evidence.get(key) != expected[key]
            for key in ("events_jsonl", "anchor_record_json", "inclusion_proofs")):
            raise ValueError("API evidence differs from the checked-out fixed fixture")
    return value


def run(base, output, root=ROOT):
    base = check_origin(base)
    output.mkdir(parents=True, exist_ok=False)
    bundle = strict_json((root / "examples/explorer-demo/bundle.json").read_text())
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                              capture_output=True, text=True, check=True).stdout.strip()
    summary = {"format": "vcp-public-probe/1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
               "source_commit": revision, "base_url": base, "first_party": True,
               "independent_reproduction": False, "external_anchor_verified": False,
               "observations": []}
    routes = {"health": "/health", "cases": "/v1/evidence-demo/cases"}
    routes.update({key: "/v1/evidence-demo/cases/" + key + "/verification" for key in CASES})
    for client in ("python", "curl", "node"):
        for name, path in routes.items():
            item = {"client": client, "route": path, "passed": False, "cryptographic_replay": None}
            try:
                status, headers, data = request(client, base + path)
                item.update(http_status=status, headers=headers, body_sha256=hashlib.sha256(data).hexdigest())
                value = validate(name, status, headers, data, bundle)
                if name in CASES:
                    capture = output / (client + "-" + name + ".json")
                    capture.write_bytes(data)
                    replay = subprocess.run(["node", str(root / "tools/replay_explorer_demo.mjs"),
                        "--api-response", str(capture.resolve()), "--case", name, "--json"],
                        capture_output=True, text=True, timeout=30)
                    if replay.returncode:
                        raise ValueError("Local SDK replay failed; exit " + str(replay.returncode))
                    report = strict_json(replay.stdout)
                    if report.get("success") is not True:
                        raise ValueError("Local SDK replay did not report success")
                    item["cryptographic_replay"] = {"local_status": value["local_status"],
                                                   "overall_status": value["overall_status"],
                                                   "fixture_bytes_match": True,
                                                   "api_claims_match_local_sdk": True}
                item["passed"] = True
            except Exception as error:
                item["error"] = str(error)[:500]
            summary["observations"].append(item)
            print(json.dumps(item, ensure_ascii=True), flush=True)
    for origin in ("https://veritaschain.org", "https://example.invalid"):
        item = {"client": "python", "test": "cors", "origin": origin, "passed": False,
                "cryptographic_replay": None}
        try:
            status, headers, data = request("python", base + routes["cases"], origin)
            item.update(http_status=status, headers=headers)
            if origin == "https://veritaschain.org":
                validate("cases", status, headers, data, bundle)
                if headers.get("access-control-allow-origin") != origin:
                    raise ValueError("Official origin not explicitly allowed")
            elif status != 403 or headers.get("access-control-allow-origin") is not None or \
                    strict_json(data).get("error") != "origin_not_allowed":
                raise ValueError("Unapproved origin was not rejected by the application")
            if "access-control-allow-credentials" in headers:
                raise ValueError("Unexpected credential-sharing header")
            item["passed"] = True
        except Exception as error:
            item["error"] = str(error)[:500]
        summary["observations"].append(item)
        print(json.dumps(item, ensure_ascii=True), flush=True)
    summary["passed"] = all(x["passed"] for x in summary["observations"])
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("PROBE_RESULT=" + ("PASS" if summary["passed"] else "FAIL"), flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=PUBLIC_ORIGIN)
    parser.add_argument("--output", type=Path, required=True, help="New directory, must not already exist")
    args = parser.parse_args()
    try:
        sys.exit(run(args.base_url, args.output))
    except Exception as error:
        print("Probe setup failed: " + str(error), file=sys.stderr)
        sys.exit(2)
