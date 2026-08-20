.PHONY: bootstrap lint test integration demo benchmark verify
bootstrap:
	cd analyzer && uv sync --dev
	cd web && npm install
lint:
	cd gateway && test -z "$$(gofmt -l .)" && go vet ./...
	cd analyzer && uv run ruff check .
test:
	cd gateway && go test -race ./...
	cd analyzer && uv run pytest -q
integration: test
demo:
	docker compose up --build
benchmark:
	cd gateway && go test -bench=. -benchmem ./...
verify: lint test
	cd web && npm run build
