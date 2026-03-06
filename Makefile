.PHONY: help install test test-unit test-integration test-cov lint format check clean run-dashboard run-pipeline-dry run-pipeline-mock

VENV   := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest
RUFF   := $(VENV)/bin/ruff
SARIF  := sarif/javascript.sarif

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install deps + dev extras
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

test: ## Run all tests
	$(PYTEST)

test-unit: ## Run only unit tests
	$(PYTEST) -m unit

test-integration: ## Run only integration tests
	$(PYTEST) -m integration

test-cov: ## Run tests with coverage report
	$(PYTEST) --cov --cov-report=term-missing

lint: ## Run ruff linter
	$(RUFF) check orchestrator/ dashboard/ tests/

format: ## Format code with ruff
	$(RUFF) format orchestrator/ dashboard/ tests/
	$(RUFF) check --fix orchestrator/ dashboard/ tests/

check: lint test ## Lint + test (CI gate)

clean: ## Remove __pycache__, .coverage, etc.
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov .pytest_cache .ruff_cache

run-dashboard: ## Start dashboard server
	$(PYTHON) dashboard/server.py

run-pipeline-dry: ## Dry-run pipeline
	$(PYTHON) orchestrator/pipeline.py --sarif $(SARIF) --mode dry-run

run-pipeline-mock: ## Mock-mode pipeline
	$(PYTHON) orchestrator/pipeline.py --sarif $(SARIF) --mode mock
