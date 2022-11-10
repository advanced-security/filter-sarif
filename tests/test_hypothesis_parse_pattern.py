# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import filter_sarif
from hypothesis import given, strategies as st


@given(line=st.text())
def test_fuzz_parse_pattern(line):
    filter_sarif.parse_pattern(line=line)

