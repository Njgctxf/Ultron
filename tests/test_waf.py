import unittest
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ultron.semantic_waf import semantic_analyzer
from ultron.waf_signatures import inspect_request

class TestUltronWAF(unittest.TestCase):

    def test_sql_tautology(self):
        hits = inspect_request("GET", "/users", "id=' OR '1'='1")
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0]["category"], "sqli")

    def test_sql_union_comment_obfuscation(self):
        hits = inspect_request("POST", "/search", "", "1'/**/UNION/**/ALL/**/SELECT/**/1,2--")
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0]["category"], "sqli")

    def test_xss_unicode_fullwidth(self):
        hits = inspect_request("GET", "/profile", "name=＜script＞alert(1)＜/script＞")
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0]["category"], "xss")

    def test_path_traversal(self):
        hits = inspect_request("GET", "/download", "file=../../../../etc/passwd")
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0]["category"], "path_traversal")

    def test_command_injection(self):
        hits = inspect_request("POST", "/ping", "", "target=127.0.0.1; cat /etc/passwd")
        self.assertTrue(len(hits) > 0)

    def test_benign_traffic(self):
        hits = inspect_request("GET", "/article", "q=documentation+union+europeenne")
        self.assertEqual(len(hits), 0)

if __name__ == "__main__":
    unittest.main()
