import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ultron.active_prober import active_prober

class TestActiveProber(unittest.TestCase):

    def test_prober_initialization(self):
        self.assertIsNotNone(active_prober)
        self.assertEqual(active_prober.timeout, 4.0)

    def test_run_active_probe_structure(self):
        # Test on dummy/mock URL
        res = active_prober.run_full_active_probe("http://127.0.0.1:5006/__sc/security/sentinel")
        self.assertIn("target", res)
        self.assertIn("total_findings", res)
        self.assertIn("findings", res)
        self.assertIn("status", res)

if __name__ == "__main__":
    unittest.main()
