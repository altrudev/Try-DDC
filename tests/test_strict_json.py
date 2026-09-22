from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tryddc_v2.canonical import strict_json_file, strict_json_loads


class StrictJSONTests(unittest.TestCase):
    def test_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate-json-key"):
            strict_json_loads('{"a":1,"a":2}')

    def test_non_finite_numbers_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite-json-number"):
            strict_json_loads('{"a":NaN}')

    def test_bounded_file_rejected_before_parse(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "large.json"
            path.write_bytes(b"{}" + b" " * 100)
            with self.assertRaisesRegex(ValueError, "json-input-too-large"):
                strict_json_file(path, max_bytes=16)


if __name__ == "__main__":
    unittest.main()
