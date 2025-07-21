# AutoTest Makefile

PYTHON := python3
PIP := pip3
PROJECT := autotest
TESTS := tests

.PHONY: help install dev-install test coverage lint format clean run docker-build docker-run

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

dev-install: ## Install development dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

test: ## Run tests
	$(PYTHON) -m pytest $(TESTS) -v

coverage: ## Run tests with coverage
	$(PYTHON) -m pytest $(TESTS) --cov=$(PROJECT) --cov-report=html --cov-report=term

lint: ## Run linters
	$(PYTHON) -m flake8 $(PROJECT) $(TESTS)
	$(PYTHON) -m mypy $(PROJECT)

format: ## Format code
	$(PYTHON) -m black $(PROJECT) $(TESTS)
	$(PYTHON) -m isort $(PROJECT) $(TESTS)

clean: ## Clean build artifacts
	rm -rf build dist *.egg-info
	rm -rf .coverage htmlcov .pytest_cache
	rm -rf autotest_results
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

run: ## Run AutoTest (example)
	$(PYTHON) autotest.py --help

docker-build: ## Build Docker image
	docker build -t autotest:latest .

docker-run: ## Run AutoTest in Docker
	docker run --rm -it \
		-v $(PWD)/autotest_results:/app/autotest_results \
		autotest:latest

check-tools: ## Check if required tools are installed
	@echo "Checking for required tools..."
	@command -v nmap >/dev/null 2>&1 && echo "✓ nmap" || echo "✗ nmap (required)"
	@command -v nuclei >/dev/null 2>&1 && echo "✓ nuclei" || echo "✗ nuclei (required)"
	@command -v msfconsole >/dev/null 2>&1 && echo "✓ metasploit" || echo "✗ metasploit (optional)"
	@command -v nikto >/dev/null 2>&1 && echo "✓ nikto" || echo "✗ nikto (optional)"
	@command -v dirb >/dev/null 2>&1 && echo "✓ dirb" || echo "✗ dirb (optional)"

setup: install check-tools ## Complete setup
	@echo "Setup complete!"

quick-scan: ## Run a quick scan on localhost
	$(PYTHON) autotest.py 127.0.0.1 --quick

demo: ## Run demo scan
	$(PYTHON) autotest.py scanme.nmap.org --quick --no-ui -o demo_results