VENV    := .venv
BIN     := $(VENV)/bin
LIMIT   ?= all

.PHONY: help setup lint test check plan apply

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

$(BIN)/ansible-playbook: requirements.txt
	python3 -m venv $(VENV)
	$(BIN)/pip install -q -r requirements.txt
	@touch $@

setup: $(BIN)/ansible-playbook ## Install pinned Ansible into .venv

lint: setup ## Syntax check and ansible-lint
	$(BIN)/ansible-playbook site.yml -i localhost, --syntax-check
	$(BIN)/ansible-lint

test: ## Run the playbook in a throwaway Debian 13 container (needs Docker)
	tests/docker-test.sh

check: lint test ## Lint and container test

plan: setup ## Dry run against inventory: show what would change (LIMIT=host)
	$(BIN)/ansible-playbook site.yml --limit $(LIMIT) --check --diff

apply: setup ## Apply to inventory (LIMIT=host)
	$(BIN)/ansible-playbook site.yml --limit $(LIMIT) --diff
