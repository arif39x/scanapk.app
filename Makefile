.PHONY: install install-api install-core test test-api test-core lint clean run

install: install-core install-api

install-core:
	pip install -e packages/scanapk-backend

install-api:
	pip install -r packages/api-server/requirements.txt
	pip install -e packages/api-server

test: test-core test-api

test-core:
	cd packages/scanapk-backend && python -m pytest tests/ -v -k "not slow"

test-api:
	cd packages/api-server && python -m pytest tests/ -v

lint:
	ruff check packages/scanapk-backend/scanapk_backend packages/api-server/api_server

run:
	./run.sh

clean:
	rm -rf packages/api-server/uploads/
	rm -f packages/api-server/jobs.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
