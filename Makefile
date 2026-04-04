.PHONY: all test test-unit test-integration clean help

# Default target
all: test-unit test-integration

## test-unit: Run unit tests for the middleware logic
test-unit:
	@echo "==> Running Unit Tests..."
	go test -v -race .

## test-integration: Run end-to-end integration tests with Docker Compose
test-integration:
	@echo "==> Running Integration Tests..."
	@cd test && go test -v -timeout 5m .

## test: Alias for unit tests
test: test-unit

## clean: Tear down any remaining Docker containers from integration tests
clean:
	@echo "==> Cleaning up Docker environment..."
	@cd test && docker-compose down -v --remove-orphans

## lint: Run go vet to check for common mistakes
lint:
	@echo "==> Running Lint..."
	go vet ./...

## vendor: Tidy and vendor dependencies
vendor:
	go mod tidy