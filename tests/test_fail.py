import pytest
import filter_sarif

def test_fail():
    with pytest.raises(SystemExit):
        filter_sarif.fail("failed")
