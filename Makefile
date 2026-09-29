.PHONY: help sync model judge judge-stop lint format typecheck test integration coverage corpus verify eval eval-dev eval-semantic ablation policy-check smoke all clean

PY := .venv/bin/python
AIRLOCK := .venv/bin/airlock

# The local judge for the semantic layer. Overridable so a CI runner can point
# at a machine that already has the model rather than downloading 2.5GB.
MODEL   ?= models/Qwen3-4B-Instruct-2507-Q4_K_M.gguf
MODEL_URL ?= https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/main/Qwen3-4B-Instruct-2507-Q4_K_M.gguf
JUDGE_HOST ?= 127.0.0.1
JUDGE_PORT ?= 8080
# The client reads AIRLOCK_JUDGE_ENDPOINT; the default has to agree with the
# server this target starts, or `make judge` then `airlock eval` silently
# measures a layer that is not there.
JUDGE   ?= http://$(JUDGE_HOST):$(JUDGE_PORT)

# The corpus is set in one workspace, and that workspace has a policy: the
# metrics service and the sharded collector it was configured to use, and
# nothing else. `make eval` measures that deployment. Plain `airlock eval` has
# no policy configured and therefore no policy layer, and that is a different
# measurement -- the README reports both.
POLICY  ?= examples/corpus-workspace-policy.json

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

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

model:  ## Download the local judge model (~2.5GB, gitignored)
	mkdir -p models
	curl -L -C - --retry 5 --retry-delay 3 -o $(MODEL) $(MODEL_URL)

judge:  ## Serve the local judge in the background (needs `make model`)
	@echo "serving $(MODEL) on $(JUDGE); stop with `make judge-stop`"
	@llama-server -m $(MODEL) --host $(JUDGE_HOST) --port $(JUDGE_PORT) \
	  -ngl 99 -c 8192 --parallel 1 >/dev/null 2>&1 &

judge-stop:  ## Stop the local judge
	-@pkill -f "llama-server.*$(notdir $(MODEL))"

eval-semantic:  ## Score the corpus with all three layers (needs `make judge`)
	$(AIRLOCK) eval --split test --layers semantic --ablation

integration:  ## Run the suite against real MCP servers (needs the integration extra)
	uv pip install --python $(PY) -e '.[integration]'
	.venv/bin/pytest tests/test_integration_real_mcp.py -q

coverage:  ## Test suite with coverage report
	.venv/bin/pytest -q --cov=airlock --cov-report=term-missing

corpus:  ## Regenerate the labelled attack corpus
	$(PY) corpus/generate.py

verify:  ## Verify the generated corpus matches the generator
	$(PY) corpus/generate.py --check

eval:  ## Score the gateway against the corpus (held-out test split, with the workspace's policy)
	$(AIRLOCK) eval --split test --policy $(POLICY) --ablation --json results/eval-test.json

eval-dev:  ## Score the dev split, for iterating on a layer
	$(AIRLOCK) eval --split dev --policy $(POLICY)

ablation:  ## Run each layer alone, to see which one earns its place
	$(AIRLOCK) eval --split test --policy $(POLICY) --ablation --layers none
	$(AIRLOCK) eval --split test --policy $(POLICY) --ablation --layers structural
	$(AIRLOCK) eval --split test --policy $(POLICY) --ablation --layers provenance
	$(AIRLOCK) eval --split test --policy $(POLICY) --ablation --layers policy

smoke:  ## End-to-end check through the installed CLI
	$(PY) scripts/smoke.py

policy-check:  ## Is the policy file still deciding every destination the traffic uses?
	$(AIRLOCK) policy-check --policy $(POLICY)

all: lint typecheck test policy-check  ## Everything CI runs

clean:  ## Remove caches and local artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage results
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
