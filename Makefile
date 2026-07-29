.NOTPARALLEL:
.PHONY: verify e2e-bootstrap

E2E_REVISION := $(shell git rev-parse --verify HEAD)
E2E_VERSION := e2e-$(E2E_REVISION)

e2e-bootstrap:
	cd tests/e2e && npm ci --ignore-scripts --no-audit --no-fund
	cd tests/e2e && npx --no-install playwright install chromium

verify:
	/usr/bin/python3 -I scripts/verify_source_tree.py $(E2E_REVISION)
	go vet ./...
	go test -race ./...
	/usr/bin/python3 -I deploy/operations_test.py
	/usr/bin/python3 -I scripts/scan_sensitive_fixtures_test.py
	/usr/bin/python3 -I scripts/release_gate_security_test.py
	cd web && npm ci --no-audit --no-fund
	cd web && npm test -- --run
	cd web && npm run build
	docker compose --env-file deploy/.env.example -f deploy/compose.yaml config >/dev/null
	git archive --format=tar $(E2E_REVISION) | docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(E2E_VERSION) \
		--build-arg REVISION=$(E2E_REVISION) \
		--build-arg SOURCE_DATE_EPOCH=0 \
		-t opswarden:$(E2E_VERSION) -
	OPSWARDEN_E2E_IMAGE_VERSION=$(E2E_VERSION) ./scripts/verify-e2e.sh
