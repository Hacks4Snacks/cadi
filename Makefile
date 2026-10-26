.PHONY: build test check clean

VERSION ?= dev

build:
	go build -trimpath -ldflags "-X ciphertrail/internal/cli.Version=$(VERSION)" -o bin/ciphertrail ./cmd/ciphertrail

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

clean:
	rm -f bin/ciphertrail
