"""Exercise the real shell entrypoint with synthetic bytes and stub executors."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('compile-and-selftest.sh')
PAYLOAD = b'SYNTHETIC installer fixture; never executable.\n'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
SUBJECT = 'Subject: /C=CY/L=Limassol/O=MetaQuotes Ltd/CN=MetaQuotes Ltd'


class InstallerGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / 'tools/mql5/compile-and-selftest.sh'
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes(SCRIPT.read_bytes())
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls.txt'
        self.work = self.root / 'work'
        for command in ('dirname', 'mkdir', 'sha256sum', 'iconv'):
            (self.bin / command).symlink_to(shutil.which(command))
        self.env = dict(os.environ, PATH=str(self.bin), DISPLAY=':synthetic',
                        MT5_WORK=str(self.work), MT5_SETUP_SHA256=DIGEST,
                        GATE_TEST_CALLS=str(self.log), GATE_TEST_SIGNATURE_SUBJECT=SUBJECT)
        for command in ('wine', 'wineboot', 'wineserver', 'timeout'):
            self.stub(command, "raise SystemExit(73)\n")
        self.stub('curl', """if os.environ.get('GATE_TEST_DOWNLOAD_FAIL'):
    raise SystemExit(22)
args = sys.argv[1:]
output = args[args.index('--output') + 1] if '--output' in args else args[args.index('-o') + 1]
Path(output).write_bytes(b'SYNTHETIC installer fixture; never executable.\\n')
""")
        self.stub('osslsigncode', """print(os.environ['GATE_TEST_SIGNATURE_SUBJECT'])
print('Signature verification: ok')
raise SystemExit(int(os.environ.get('GATE_TEST_SIGNATURE_EXIT', '0')))
""")

    def stub(self, command, body):
        path = self.bin / command
        path.write_text(f'#!{sys.executable}\nimport os, sys\nfrom pathlib import Path\n'
                        f"with open(os.environ['GATE_TEST_CALLS'], 'a') as log: log.write({command!r} + '\\n')\n" + body)
        path.chmod(0o755)

    def run_script(self):
        result = subprocess.run(['/bin/bash', str(self.script)], env=self.env,
                                capture_output=True, text=True, timeout=10)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return result, calls

    def assert_denied_without_wine(self, expected_message):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(expected_message, result.stderr)
        self.assertFalse(set(calls) & {'wine', 'wineboot', 'wineserver', 'timeout'}, calls)
        return calls

    def test_missing_reviewed_pin_stops_before_download(self):
        self.env.pop('MT5_SETUP_SHA256')
        self.assertEqual(self.assert_denied_without_wine('reviewed 64-digit SHA-256'), [])

    def test_malformed_pin_stops_before_download(self):
        self.env['MT5_SETUP_SHA256'] = 'not-a-sha256'
        self.assertEqual(self.assert_denied_without_wine('reviewed 64-digit SHA-256'), [])

    def test_mismatched_download_cannot_start_wine(self):
        self.env['MT5_SETUP_SHA256'] = '0' * 64
        calls = self.assert_denied_without_wine('SHA-256 mismatch')
        self.assertEqual(calls, ['curl'])

    def test_signature_failure_cannot_pass_with_success_text(self):
        self.env['GATE_TEST_SIGNATURE_EXIT'] = '1'
        self.assert_denied_without_wine('signature verification failed')

    def test_wrong_publisher_cannot_start_wine(self):
        self.env['GATE_TEST_SIGNATURE_SUBJECT'] = 'Subject: /CN=Another Publisher'
        self.assert_denied_without_wine('publisher did not verify')

    def test_signature_verifier_is_mandatory(self):
        (self.bin / 'osslsigncode').unlink()
        self.assertEqual(self.assert_denied_without_wine('osslsigncode not found'), [])

    def test_failed_download_cannot_start_wine(self):
        self.env['GATE_TEST_DOWNLOAD_FAIL'] = '1'
        self.assert_denied_without_wine('download failed')

    def test_existing_prefix_cannot_bypass_installer_integrity(self):
        existing = self.work / 'prefix/drive_c/Program Files/MetaTrader 5/MetaEditor64.exe'
        existing.parent.mkdir(parents=True)
        existing.write_bytes(b'synthetic cached installation')
        self.env['MT5_SETUP_SHA256'] = '0' * 64
        self.assert_denied_without_wine('SHA-256 mismatch')

    def test_cached_installer_is_rechecked(self):
        cached = self.work / 'dl/mt5setup.exe'
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b'tampered synthetic bytes')
        self.assertEqual(self.assert_denied_without_wine('SHA-256 mismatch'), [])

    def test_matching_digest_and_signature_reach_only_stubbed_wine(self):
        result, calls = self.run_script()
        # The stub wineboot deliberately stops before any EXE can be executed.
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(calls[:3], ['curl', 'osslsigncode', 'wineboot'])
        self.assertNotIn('wine', calls)
        self.assertNotIn('timeout', calls)


if __name__ == '__main__':
    unittest.main()
