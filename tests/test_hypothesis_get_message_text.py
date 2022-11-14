# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import filter_sarif
import typing
from hypothesis import given, strategies as st


@given(result=st.from_type(typing.Dict[str, typing.Dict]))
def test_fuzz_get_message_text(result):
    filter_sarif.get_message_text(result=result)

