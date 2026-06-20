import unittest

from security_review_gate.diff_parser import parse_unified_diff


DIFF = """diff --git a/src/auth.py b/src/auth.py
index 111..222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,2 +1,3 @@
-verify = True
+verify = False
+token = request.headers.get("token")
 context = "unchanged"
"""


class DiffParserTests(unittest.TestCase):
    def test_parses_file_and_changed_lines(self) -> None:
        parsed = parse_unified_diff(DIFF)

        self.assertEqual(len(parsed.files), 1)
        self.assertEqual(parsed.files[0].path, "src/auth.py")
        self.assertEqual(parsed.lines_added, 2)
        self.assertEqual(parsed.lines_removed, 1)

    def test_rejects_oversized_diff(self) -> None:
        with self.assertRaisesRegex(ValueError, "2 MiB"):
            parse_unified_diff("x" * (2 * 1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
