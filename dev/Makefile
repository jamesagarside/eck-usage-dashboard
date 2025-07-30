.PHONY: help setup install test run clean config

# Variables
PYTHON := python3
PIP := pip3
VENV := venv
SCRIPT := ../eck_usage_monitor.py
REQUIREMENTS := ../requirements.txt
CONFIG_EXAMPLE := ../config.env.example
CONFIG := ../config.env

help: ## Show this help message
	@echo "ECK Usage Monitor Development Setup - Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: venv-install config ## Complete development setup (virtual environment + dependencies + config)
	@echo "Development setup complete!"
	@echo "Activate virtual environment with: source $(VENV)/bin/activate"
	@echo "Edit $(CONFIG) with your Elasticsearch details before running."

install: ## Install dependencies globally
	$(PIP) install -r $(REQUIREMENTS)

venv: ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	@echo "Virtual environment created. Activate with: source $(VENV)/bin/activate"

venv-install: venv ## Create virtual environment and install dependencies
	$(VENV)/bin/pip install -r $(REQUIREMENTS)
	@echo "Dependencies installed in virtual environment"

config: ## Create config file from example
	@if [ ! -f $(CONFIG) ]; then \
		cp $(CONFIG_EXAMPLE) $(CONFIG); \
		echo "Created $(CONFIG) from example. Please edit with your values."; \
	else \
		echo "$(CONFIG) already exists."; \
	fi

validate-config: ## Validate configuration file
	@if [ -f $(CONFIG) ]; then \
		echo "Validating configuration in $(CONFIG)..."; \
		$(PYTHON) $(SCRIPT) --config-file $(CONFIG) --dry-run; \
	else \
		echo "No config file found. Run 'make config' first."; \
	fi

test: ## Run the script with test/dry-run mode
	@if [ -f $(CONFIG) ]; then \
		echo "Loading configuration from $(CONFIG)..."; \
		$(PYTHON) $(SCRIPT) --config-file $(CONFIG) --dry-run --verbose; \
	else \
		echo "No config file found. Run 'make config' first or provide arguments manually."; \
		echo "Usage: $(PYTHON) $(SCRIPT) --elasticsearch-url <url> --api-key <key> --dry-run --verbose"; \
	fi

test-venv: ## Run test using virtual environment
	@if [ -f $(CONFIG) ]; then \
		echo "Loading configuration from $(CONFIG)..."; \
		$(VENV)/bin/python $(SCRIPT) --config-file $(CONFIG) --dry-run --verbose; \
	else \
		echo "No config file found. Run 'make config' first."; \
	fi

run: ## Run the monitor script
	@if [ -f $(CONFIG) ]; then \
		echo "Loading configuration from $(CONFIG)..."; \
		$(PYTHON) $(SCRIPT) --config-file $(CONFIG) --verbose; \
	else \
		echo "No config file found. Run 'make config' first or provide arguments manually."; \
		echo "Usage: $(PYTHON) $(SCRIPT) --elasticsearch-url <url> --api-key <key>"; \
	fi

run-venv: ## Run the monitor script using virtual environment
	@if [ -f $(CONFIG) ]; then \
		echo "Loading configuration from $(CONFIG)..."; \
		$(VENV)/bin/python $(SCRIPT) --config-file $(CONFIG) --verbose; \
	else \
		echo "No config file found. Run 'make config' first."; \
	fi

dev: ## Run in development mode with verbose output and template creation
	@if [ -f $(CONFIG) ]; then \
		echo "Loading configuration from $(CONFIG)..."; \
		$(PYTHON) $(SCRIPT) --config-file $(CONFIG) --create-templates --verbose; \
	else \
		echo "No config file found. Run 'make config' first."; \
	fi

clean: ## Clean up temporary files and virtual environment
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find .. -type f -name "*.pyc" -delete
	find .. -type d -name "__pycache__" -delete
	rm -rf $(VENV)
