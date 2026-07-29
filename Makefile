.NOTPARALLEL:
.PHONY: verify _verify-locked e2e-bootstrap

ifneq ($(filter _verify-locked,$(MAKECMDGOALS)),)
E2E_REVISION := $(shell GIT_NO_REPLACE_OBJECTS=1 git --no-replace-objects rev-parse --verify HEAD)
E2E_VERSION := e2e-$(E2E_REVISION)
endif

e2e-bootstrap:
	cd tests/e2e && npm ci --ignore-scripts --no-audit --no-fund
	cd tests/e2e && npx --no-install playwright install chromium

verify:
	/usr/bin/python3 -I scripts/e2e_lock.py "$(CURDIR)" -- \
		/usr/bin/make --no-print-directory -f "$(CURDIR)/Makefile" _verify-locked

_verify-locked:
	/usr/bin/python3 -I scripts/verify_source_tree.py $(E2E_REVISION)
	go vet ./...
	go test -race ./...
	GOTOOLCHAIN=go1.25.12 go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
	/usr/bin/python3 -I deploy/operations_test.py
	/usr/bin/python3 -I scripts/scan_sensitive_fixtures_test.py
	/usr/bin/python3 -I scripts/release_gate_security_test.py
	cd web && npm ci --no-audit --no-fund
	cd web && npm audit --omit=dev --audit-level=moderate
	cd web && npm test -- --run
	cd web && npm run build
	cd tests/e2e && npm audit --omit=dev --audit-level=moderate
	docker compose --env-file deploy/.env.example -f deploy/compose.yaml config >/dev/null
	GIT_NO_REPLACE_OBJECTS=1 git --no-replace-objects archive --format=tar $(E2E_REVISION) | docker build -f deploy/Dockerfile \
		--build-arg VERSION=$(E2E_VERSION) \
		--build-arg REVISION=$(E2E_REVISION) \
		--build-arg SOURCE_DATE_EPOCH=0 \
		-t opswarden:$(E2E_VERSION) -
	OPSWARDEN_E2E_IMAGE_VERSION=$(E2E_VERSION) ./scripts/verify-e2e.sh
