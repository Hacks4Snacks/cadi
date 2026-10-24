.PHONY: build test check clean

build:
	go build -trimpath -o bin/ciphertrail ./cmd/ciphertrail

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

clean:
	rm -f bin/ciphertrail
