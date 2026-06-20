import unittest

from security_review_gate.baseline import baseline_decision
from security_review_gate.diff_parser import parse_unified_diff
from security_review_gate.features import extract_features

from test_diff_parser import DIFF


class FeatureTests(unittest.TestCase):
    def test_extracts_security_signals(self) -> None:
        features = extract_features(parse_unified_diff(DIFF))

        self.assertEqual(features.sensitive_paths, 1)
        self.assertGreaterEqual(features.auth_signals, 1)
        self.assertEqual(features.security_disable_signals, 1)

    def test_baseline_recommends_high_review(self) -> None:
        decision = baseline_decision(extract_features(parse_unified_diff(DIFF)))

        self.assertEqual(decision.level, "high")
        self.assertGreaterEqual(decision.score, 55)
        self.assertNotIn("False", " ".join(decision.signals))

    def test_documentation_only_change_is_low(self) -> None:
        diff = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
+Documentação atualizada.
"""
        decision = baseline_decision(extract_features(parse_unified_diff(diff)))
        self.assertEqual(decision.level, "low")
        self.assertEqual(decision.score, 0)


if __name__ == "__main__":
    unittest.main()
