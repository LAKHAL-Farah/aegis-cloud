.PHONY: up down spike fmt
up:
	docker compose up -d
	@echo "waiting for LocalStack..."; until curl -sf localhost:4566/_localstack/health >/dev/null; do sleep 2; done; echo ready
down:
	docker compose down -v
spike:
	cd spike && ./spike.sh
fmt:
	terraform fmt -recursive
