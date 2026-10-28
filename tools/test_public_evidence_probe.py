"""Transport/contract unit tests, not tests of the real public host or SDK crypto."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import threading
import unittest

spec = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("probe_public_evidence.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
BUNDLE = {"sdk_version": "0.1.0", "spec_version": "1.2.0", "cases": [
    {"id": key, "events_jsonl": '{"TimestampInt":1793145600123456789}\n',
     "anchor_record_json": "{}", "inclusion_proofs": []} for key in probe.CASES]}
GOOD_HEADERS = {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"}


class ProbeTest(unittest.TestCase):
    def test_approved_origin_only(self):
        self.assertEqual(probe.check_origin(probe.PUBLIC_ORIGIN + "/"), probe.PUBLIC_ORIGIN)
        self.assertEqual(probe.check_origin("http://127.0.0.1:4567"), "http://127.0.0.1:4567")
        for value in ["http://169.254.169.254", "https://example.com", "https://user:pw@example.com",
                      probe.PUBLIC_ORIGIN + "/path", probe.PUBLIC_ORIGIN + "?x=y", "file:///tmp/data"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.check_origin(value)

    def test_reject_duplicate_keys_and_nonfinite_json(self):
        for value in ['{"a":1,"a":2}', '{"nested":{"x":1,"x":2}}', '{"x":NaN}']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                probe.strict_json(value)

    def test_http_error_is_not_a_crypto_verdict(self):
        with self.assertRaisesRegex(ValueError, "HTTP 403 / edge error 1010; not an evidence verdict"):
            probe.validate("intact", 403, {}, b"error code: 1010", BUNDLE)

    def test_no_success_for_html_or_cacheable_result(self):
        for headers in [{"content-type": "text/html"}, {"content-type": "application/json"}]:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                probe.validate("health", 200, headers, b'{}', BUNDLE)

    def test_directory_duplicates_are_rejected(self):
        value = {"format": "vcp-evidence-demo/1", "sdk_version": "0.1.0", "spec_version": "1.2.0",
                 "cases": [{"id": "intact"}] * 3}
        with self.assertRaisesRegex(ValueError, "Case-directory"):
            probe.validate("cases", 200, GOOD_HEADERS, json.dumps(value).encode(), BUNDLE)

    def test_all_three_fixed_outcomes_and_raw_strings(self):
        for name, statuses in probe.CASES.items():
            expected = next(x for x in BUNDLE["cases"] if x["id"] == name)
            value = {"format": "vcp-evidence-demo-verification/1", "case_id": name,
                     "local_status": statuses[0], "overall_status": statuses[1],
                     "evidence": {key: expected[key] for key in
                                  ("events_jsonl", "anchor_record_json", "inclusion_proofs")}}
            with self.subTest(name=name):
                self.assertEqual(probe.validate(name, 200, GOOD_HEADERS, json.dumps(value).encode(), BUNDLE), value)
                value["evidence"]["events_jsonl"] = value["evidence"]["events_jsonl"].replace("6789", "6000")
                with self.assertRaisesRegex(ValueError, "differs"):
                    probe.validate(name, 200, GOOD_HEADERS, json.dumps(value).encode(), BUNDLE)

    def test_wrong_case_cannot_pass_with_identical_status(self):
        value = {"format": "vcp-evidence-demo-verification/1", "case_id": "missing-key"}
        with self.assertRaisesRegex(ValueError, "identity"):
            probe.validate("intact", 200, GOOD_HEADERS, json.dumps(value).encode(), BUNDLE)

    def test_three_real_clients_bounded_no_redirect_honest_identity(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                seen.append((self.path, self.headers.get("User-Agent"), self.headers.get("Origin")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/unexpected")
                    self.end_headers()
                    return
                body = b'x' * (probe.LIMIT + 1) if self.path == "/large" else b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = "http://127.0.0.1:" + str(server.server_port)
        try:
            for client in ("python", "curl", "node"):
                with self.subTest(client=client):
                    if client != "python" and not shutil.which(client):
                        self.fail(client + " required for the transport tests")
                    status, _, body = probe.request(client, base + "/ok")
                    self.assertEqual(status, 200)
                    self.assertEqual(probe.strict_json(body), {"status": "ok"})
                    status, _, _ = probe.request(client, base + "/redirect")
                    self.assertEqual(status, 302)
                    with self.assertRaises(ValueError):
                        probe.request(client, base + "/large")
            self.assertTrue(all(agent == probe.AGENT and origin is None for _, agent, origin in seen))
            self.assertFalse(any(path == "/unexpected" for path, _, _ in seen))
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
