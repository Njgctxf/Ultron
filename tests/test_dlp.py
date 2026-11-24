import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ultron.dlp_engine import dlp_engine

class TestDLPEngine(unittest.TestCase):

    def test_aws_key_redaction(self):
        body = '{"secret": "AKIAIOSFODNN7EXAMPLE"}'
        sanitized, leaks = dlp_engine.sanitize_response(body, "application/json")
        self.assertTrue(len(leaks) > 0)
        self.assertIn("REDACTED", sanitized)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)

    def test_private_key_redaction(self):
        body = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n-----END PRIVATE KEY-----"
        sanitized, leaks = dlp_engine.sanitize_response(body, "text/plain")
        self.assertTrue(len(leaks) > 0)
        self.assertIn("[REDACTED_PRIVATE_KEY_BY_ULTRON_DLP]", sanitized)

if __name__ == "__main__":
    unittest.main()
