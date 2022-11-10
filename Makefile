all: lint test

.PHONY: test lint clean

test:
	# unit tests
	python3 -m pip install pytest --user
	-python3 -m pytest ./tests

	# end-to-end tests
	./filter_sarif.py --help 2>/dev/null >/dev/null
	./filter_sarif.py --input test_input.sarif --output test_output_none.sarif -- '-**'
	jq -e '.runs[0].results | length == 0' test_output_none.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all.sarif -- '-**' '+**'
	jq -e '.runs[0].results | length == 1' test_output_all.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py.sarif -- '-**' '*.py'
	jq -e '.runs[0].results | length == 1' test_output_all_py.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_all_rules.sarif -- '-**' '*.py:**'
	jq -e '.runs[0].results | length == 1' test_output_all_py_all_rules.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_code_injection_rule.sarif -- '-**' '*.py:py/code-injection'
	jq -e '.runs[0].results | length == 1' test_output_all_py_code_injection_rule.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_non-existent_rule.sarif -- '-**' '*.py:py/invented-nonsense-fdshjfdsbf'
	jq -e '.runs[0].results | length == 0' test_output_all_py_non-existent_rule.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_code_injection_rule_wildcard_message.sarif -- '-**' '*.py:py/code-injection:^.*$$'
	jq -e '.runs[0].results | length == 1' test_output_all_py_code_injection_rule_wildcard_message.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_code_injection_rule_partial_message.sarif -- '-**' '*.py:py/code-injection:flows to here'
	jq -e '.runs[0].results | length == 1' test_output_all_py_code_injection_rule_partial_message.sarif
	./filter_sarif.py --input test_input.sarif --output test_output_all_py_code_injection_rule_non-matching_message.sarif -- '-**' '*.py:py/code-injection:flows to the sea'
	jq -e '.runs[0].results | length == 0' test_output_all_py_code_injection_rule_non-matching_message.sarif

lint:
	python3 -m pip install -r dev-requirements.txt
	python3 -m yapf -i --style='{based_on_style: google, column_limit: 120, indent_width: 4}' filter_sarif.py
	python3 -m flake8 --ignore=E501,W504 filter_sarif.py
	python3 -m mypy --strict filter_sarif.py
	python3 -m bandit -r .

clean:
	rm __pycache__/*.pyc rm ./test_output_*.sarif
