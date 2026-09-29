.PHONY: help sync lint format typecheck test coverage corpus verify eval smoke all clean

PY := .venv/bin/python
AIRLOCK := .venv/bin/airlock

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

sync:  ## Install dependencies
	uv sync --extra dev

lint:  ## Check formatting and style
	.venv/bin/ruff format --check .
	.venv/bin/ruff check .

format:  ## Apply formatting and autofixes
	.venv/bin/ruff format .
	.venv/bin/ruff check --fix .

typecheck:  ## Static types (strict)
	.venv/bin/mypy src

test:  ## Run the test suite
	.venv/bin/pytest -q

coverage:  ## Test suite with coverage report
	.venv/bin/pytest -q --cov=airlock --cov-report=term-missing

corpus:  ## Regenerate the labelled attack corpus
	$(PY) corpus/generate.py

verify:  ## Verify the generated corpus matches the generator
	$(PY) corpus/generate.py --check

eval:  ## Score the gateway against the corpus (held-out test split)
	$(AIRLOCK) eval --split test --ablation --json results/eval-test.json

smoke:  ## End-to-end check through the installed CLI
	$(PY) scripts/smoke.py

all: lint typecheck test  ## Everything CI runs

clean:  ## Remove caches and local artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage results
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
