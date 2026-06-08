# Embargo — common tasks. Run `make` (or `make help`) to list targets.
.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
HOST    ?= localhost

.PHONY: help up down restart logs ps health onboard seed-check \
        test test-engine test-gateway test-admission test-console clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## ---- run the stack ----
up: ## Build + start the full stack, wait for health, print next steps
	@scripts/quickstart.sh

down: ## Stop the stack (keep data)
	@$(COMPOSE) down

restart: down up ## Restart the stack

clean: ## Stop the stack and remove volumes (Postgres data + certs)
	@$(COMPOSE) down -v

logs: ## Tail logs from all services
	@$(COMPOSE) logs -f

ps: ## Show service status
	@$(COMPOSE) ps

health: ## Curl the engine readiness endpoint
	@curl -fsS http://localhost:9090/health/ready && echo "  engine ready" || echo "engine not ready"

## ---- use it ----
onboard: ## Point the current project's .npmrc at the gateway (REGISTRY=... to override)
	@scripts/onboard.sh $(REGISTRY)

## ---- tests ----
test: test-engine test-gateway test-admission test-console ## Run every component's tests

test-engine: ## Engine core unit + fixture tests (no services needed)
	@cd engine && PROTOC=$$(which protoc) cargo test -p embargo-core

test-gateway: ## Gateway (L1) tests
	@cd gateway && npm ci --silent && npm test

test-admission: ## Admission (L2) tests
	@cd admission && npm ci --silent && npm test

test-console: ## Console typecheck + lint + build
	@cd console && npm ci --silent && npm run typecheck && npm run lint && npm run build
