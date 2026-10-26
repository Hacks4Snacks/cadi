.PHONY: build test check release clean

VERSION ?= dev
BINARY ?= bin/cadi
DIST_DIR ?= dist

build:
	go build -trimpath -ldflags "-X cadi/internal/cli.Version=$(VERSION)" -o "$(BINARY)" ./cmd/cadi

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

release:
	@set -eu; \
	if ! printf '%s\n' "$(VERSION)" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$'; then \
		echo 'VERSION must be a stable release tag, for example v0.1.0' >&2; \
		exit 1; \
	fi; \
	mkdir -p "$(DIST_DIR)"; \
	stage=$$(mktemp -d "$(DIST_DIR)/.staging.XXXXXX"); \
	trap 'rm -rf "$$stage"' EXIT; \
	cp README.md "$$stage/"; \
	cp -R docs "$$stage/"; \
	mkdir -p "$$stage/third_party/cyclonedx"; \
	cp internal/export/cyclonedx/schema/LICENSE internal/export/cyclonedx/schema/NOTICE "$$stage/third_party/cyclonedx/"; \
	for file in LICENSE NOTICE; do \
		if [ -f "$$file" ]; then cp "$$file" "$$stage/"; fi; \
	done; \
	: > "$(DIST_DIR)/SHA256SUMS"; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		name="cadi_$(VERSION)_$${os}_$${arch}"; \
		binary=cadi; extension=tar.gz; \
		if [ "$$os" = windows ]; then binary=cadi.exe; extension=zip; fi; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(MAKE) --no-print-directory build BINARY="$$stage/$$binary"; \
		if [ "$$extension" = zip ]; then \
			rm -f "$(DIST_DIR)/$$name.zip"; \
			(cd "$$stage" && zip -qr "../$$name.zip" .); \
		else \
			tar -czf "$(DIST_DIR)/$$name.tar.gz" -C "$$stage" .; \
		fi; \
		rm -f "$$stage/$$binary"; \
		(cd "$(DIST_DIR)" && shasum -a 256 "$$name.$$extension") >> "$(DIST_DIR)/SHA256SUMS"; \
	done

clean:
	rm -f "$(BINARY)"
