.PHONY: install install-web test test-unit test-integration lint format docker docker-prod docker-down smoke clean quality

install:
	pip install -e ".[dev]"
	pre-commit install

install-web:
	cd clients/web && npm install

test:
	pytest tests/ -v --cov=nova_arsenal --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v -m integration

lint:
	ruff check .
	cd clients/web && npm run lint

format:
	ruff check --fix .
	ruff format .
	cd clients/web && npm run format

docker:
	docker compose build
	docker compose up -d

docker-prod:
	docker compose -f docker-compose.prod.yml build
	docker compose -f docker-compose.prod.yml up -d

docker-down:
	docker compose down -v

smoke:
	python -m nova_arsenal.cli --help
	cd clients/web && npm run build

clean:
	rm -rf __pycache__ .pytest_cache .coverage .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
	cd clients/web && rm -rf .next node_modules 2>/dev/null || true

quality: lint test
	@echo "✓ Quality checks passed"

.DEFAULT_GOAL := help

help:
	@echo "Nova-Arsenal Development Commands"
	@echo "================================="
	@echo "make install        - Install Python package and pre-commit hooks"
	@echo "make install-web    - Install web client dependencies"
	@echo "make test           - Run all tests with coverage"
	@echo "make test-unit      - Run unit tests only"
	@echo "make test-integration - Run integration tests only"
	@echo "make lint           - Run linting (ruff + web lint)"
	@echo "make format         - Auto-format code"
	@echo "make docker         - Build and start all services"
	@echo "make docker-prod    - Build and start production services"
	@echo "make docker-down    - Stop all services and remove volumes"
	@echo "make smoke          - Quick sanity check"
	@echo "make quality        - Full quality gate (lint + test)"
	@echo "make clean          - Remove caches and docker volumes"
