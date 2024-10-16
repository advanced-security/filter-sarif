import json
import unittest
import filter_sarif


class TestFilter(unittest.TestCase):
    def setUp(self) -> None:
        with open("tests/data/cpp.sarif") as f:
            self.sarif = json.load(f)
        self.assertEqual(len(self.sarif["runs"][0]["results"]), 3)
        return super().setUp()

    def test_exclude_all(self):
        patterns = ["-**/*"]
        parsed_patterns = [filter_sarif.parse_pattern(p) for p in patterns]
        sarif = filter_sarif.filter_sarif(self.sarif, parsed_patterns)
        # Excluding everything
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)

    def test_exclude_all_except_one(self):
        # -**/* [exclude everything first], +src/** [include everything in src]
        patterns = ["-**/*", "+src/**"]
        parsed_patterns = [filter_sarif.parse_pattern(p) for p in patterns]
        sarif = filter_sarif.filter_sarif(self.sarif, parsed_patterns)
        # Only 1
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
