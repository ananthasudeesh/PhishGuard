.PHONY: install run test lint clean

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

run:
	.venv/bin/streamlit run app.py

test:
	PYTHONPATH=src .venv/bin/pytest -q

lint:
	.venv/bin/python -m compileall -q src app.py

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov
