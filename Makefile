.PHONY: help up down logs test lint simulate dashboard clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Build and start the lab
	docker compose up --build -d

down: ## Stop the lab
	docker compose down

logs: ## Follow sensor and edge logs
	docker compose logs -f

test: ## Run the test suite
	python3 -m pytest

simulate: ## Generate synthetic traffic against the local lab
	python3 tools/simulate_traffic.py --rounds 20

dashboard: ## Print the dashboard URL
	@echo "http://127.0.0.1:8081/_edl/dashboard"

clean: ## Remove local database and caches
	rm -rf data/*.db data/*.db-wal data/*.db-shm .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
