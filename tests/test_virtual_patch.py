import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ultron.virtual_patching import virtual_patch_engine

class TestVirtualPatching(unittest.TestCase):

    def test_instant_virtual_patch(self):
        # Create virtual patch on /api/payment
        p = virtual_patch_engine.create_patch(
            name="Hotfix ZeroDay Payment",
            target_path="^/api/payment.*$",
            block_pattern="amount=-[0-9]+",
            action="BLOCK"
        )
        self.assertEqual(p["status"], "ACTIVE")

        # Test matching malicious payload
        blocked = virtual_patch_engine.inspect_request("POST", "/api/payment", "", "amount=-500&account=123")
        self.assertIsNotNone(blocked)
        self.assertTrue(blocked["blocked"])

        # Test normal payload
        clean = virtual_patch_engine.inspect_request("POST", "/api/payment", "", "amount=500&account=123")
        self.assertIsNone(clean)

if __name__ == "__main__":
    unittest.main()
