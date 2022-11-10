# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import globber
from hypothesis import given, strategies as st


@given(pattern=st.text(), file_name=st.text())
def test_fuzz_match(pattern, file_name):
    globber.match(pattern=pattern, file_name=file_name)

