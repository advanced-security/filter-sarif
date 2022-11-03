test:
	./filter_sarif.py --help 2>/dev/null

lint:
	python3 -m pip install -r dev-requirements.txt
	python3 -m yapf -i --style='{based_on_style: google, column_limit: 120, indent_width: 4}' filter_sarif.py
	python3 -m flake8 --ignore=E501,W504 filter_sarif.py
	python3 -m mypy --strict filter_sarif.py
	python3 -m bandit -r .

clean:
	rm __pycache__/*.pyc
