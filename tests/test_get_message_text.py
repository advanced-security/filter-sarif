import filter_sarif

def test_get_message_test():
    filter_sarif.get_message_text({"message": {"text": "hello"}}) == "hello"
    filter_sarif.get_message_text({"message": {"markdown": "hello"}}) == "hello"
    filter_sarif.get_message_text({"message": {"id": "hello"}}) is None
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": ["world"]}}) == "hello world"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": ["world", "extra"]}}) == "hello world"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": []}}) == "hello {0}"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": None}}) == "hello {0}"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": "world"}}) == "hello {0}"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": 1}}) == "hello {0}"
    filter_sarif.get_message_text({"message": {"text": "hello {0}", "arguments": {}}}) == "hello {0}"
    filter_sarif.get_message_text({"msg": {"text": "hello"}}) is None
