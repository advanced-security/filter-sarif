import json
import unittest
import filter_sarif


class TestPatternParsing(unittest.TestCase):
    def test_parse_pattern_files(self):
        # `-` doesn't set sign to True
        self.assertEqual(filter_sarif.parse_pattern("-**/*"), (False, "**/*", "**"))
        self.assertEqual(filter_sarif.parse_pattern("+src/**"), (True, "src/**", "**"))
        # No rule but still has a `:`
        self.assertEqual(
            filter_sarif.parse_pattern("-**/*Test*.java:**"),
            (False, "**/*Test*.java", "**"),
        )

    def test_underscores(self):
        self.assertEqual(
            filter_sarif.parse_pattern("-_codeql_build_dir/**"),
            (False, "_codeql_build_dir/**", "**"),
        )

    def test_parse_pattern_rules(self):
        self.assertEqual(
            filter_sarif.parse_pattern("-**/*:rule"), (False, "**/*", "rule")
        )
        self.assertEqual(
            filter_sarif.parse_pattern("+src/**:rule"), (True, "src/**", "rule")
        )

        self.assertEqual(
            filter_sarif.parse_pattern("+src/**:rule"), (True, "src/**", "rule")
        )
