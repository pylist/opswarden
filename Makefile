.PHONY: verify verify-go verify-web verify-compose verify-image verify-e2e verify-sensitive

E2E_VERSION := e2e
E2E_REVISION := $(shell git rev-parse --verify HEAD)

verify: verify-go verify-web verify-compose verify-image verify-e2e verify-sensitive

verify-go:
	go vet ./...
	go test -race ./...
	/usr/bin/python3 -I deploy/operations_test.py

verify-web:
	cd web && npm ci --no-audit --no-fund
	cd web && npm test -- --run
	cd web && npm run build

verify-compose:
	docker compose --env-file deploy/.env.example -f deploy/compose.yaml config >/dev/null

verify-image:
	docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(E2E_VERSION) \
		--build-arg REVISION=$(E2E_REVISION) \
		--build-arg SOURCE_DATE_EPOCH=0 \
		-t opswarden:$(E2E_VERSION) .

verify-e2e:
	cd tests/e2e && npm ci --ignore-scripts --no-audit --no-fund
	cd tests/e2e && npx playwright install chromium
	cd tests/e2e && npx playwright test

verify-sensitive:
	./scripts/scan-sensitive-fixtures.sh
