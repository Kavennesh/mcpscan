.PHONY: install images lint test check clean

install:
	uv sync

images:
	docker build -t mcpscan/fetcher:0.1.0 -f sandbox/Dockerfile.fetcher sandbox/
	docker build -t mcpscan/runner:0.1.0  -f sandbox/Dockerfile.runner  sandbox/

lint:
	uv run ruff check src/ tests/
	uv run mypy src/

test:
	uv run pytest -q

check: lint test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build
