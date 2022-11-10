import pytest
import filter_sarif

def test_parse_pattern():
    # all files, no other parts to the pattern
    assert filter_sarif.parse_pattern(r"**") == (True, "**", None, None)
    # all files, all rules, no message filtering
    assert filter_sarif.parse_pattern(r"**:**") == (True, "**", "**", None)
    # all files, all rules, positive message filtering
    assert filter_sarif.parse_pattern(r"**:**:.*") == (True, "**", "**", ".*")
    # all "*.java" files, all rules, no message filtering
    assert filter_sarif.parse_pattern(r"**/*.java:**") == (True, "**/*.java", "**", None)
    # all "*.java" files, just one rule, no message filtering
    assert filter_sarif.parse_pattern(r"**/*.java:java/some-rule-id") == (True, "**/*.java", "java/some-rule-id", None)
    # all "*.java" files, just one rule, positive message filtering
    assert filter_sarif.parse_pattern(r"**/*.java:java/some-rule-id:^with a regex$") == (True, "**/*.java", "java/some-rule-id", "^with a regex$")
    # postive rule to include all file patterns
    assert filter_sarif.parse_pattern(r"+**") == (True, "**", None, None)
    # negative rule to exclude all file patterns
    assert filter_sarif.parse_pattern(r"-**") == (False, "**", None, None)
    # this second glob is invalid, but not our job to validate it
    assert filter_sarif.parse_pattern(r"-**:-**") == (False, "**", "-**", None)
    # escape the leading - to make it literal (so just match on files called '-')
    assert filter_sarif.parse_pattern(r"\-") == (True, "-", None, None)
    # escape the leading - to make it literal (so just match on files called '-') with any rule
    assert filter_sarif.parse_pattern(r"\-:**") == (True, "-", "**", None)
    with pytest.raises(ValueError):
        filter_sarif.parse_pattern(r"1:2:3:4")
