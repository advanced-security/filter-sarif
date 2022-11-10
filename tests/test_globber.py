import pytest
import globber

def test_globber():
    # positive tests
    assert globber.match("foo.java", "foo.java")
    assert globber.match("*", "foo.java")
    assert globber.match("**", "foo.java")
    assert globber.match("**/*.java", "foo/foo.java")
    assert globber.match("foo/foo.java", "foo/foo.java")
    assert globber.match("foo/foo*", "foo/foo.java")
    assert globber.match("foo/foo.*", "foo/foo.java")
    assert globber.match("java/*", "java/some-rule-id")

    # negative tests
    with pytest.raises(ValueError):
        globber.match("foo/foo**", "foo/foo.java")
    assert not globber.match("*.java", "foo/foo.js")
    assert not globber.match("*.java", "foo/foo.java")
    assert not globber.match("foo/*", "bar/bar.js")
    assert not globber.match("js/*", "java/some-rule-id")

