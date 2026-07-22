import json
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
import filter_sarif


class TestFilter(unittest.TestCase):
    def setUp(self) -> None:
        sarif_path = Path(__file__).parent / "data" / "cpp.sarif"
        with sarif_path.open() as f:
            self.sarif = json.load(f)
        self.assertEqual(len(self.sarif["runs"][0]["results"]), 3)
        return super().setUp()

    def _run_filter(self, patterns):
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.sarif"
            output_path = Path(temp_dir) / "output.sarif"
            with input_path.open("w") as input_file:
                json.dump(self.sarif, input_file)

            args = Namespace(
                input=str(input_path),
                output=str(output_path),
                split_lines=False,
                severity=None,
                patterns=patterns,
            )
            filter_sarif.filter_sarif(args)

            with output_path.open() as f:
                return json.load(f)

    def test_exclude_all(self):
        patterns = ["-**/*"]
        sarif = self._run_filter(patterns)
        # Excluding everything
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)

    def test_exclude_all_except_one(self):
        # -**/* [exclude everything first], +src/** [include everything in src]
        patterns = ["-**/*", "+src/**"]
        sarif = self._run_filter(patterns)
        # Only 1
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
