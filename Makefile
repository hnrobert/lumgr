BINARY_NAME=lumgrd

.PHONY: build run test

build:
	go build -o bin/$(BINARY_NAME) ./cmd/lumgrd

run:
	LUMGR_LISTEN=:14392 go run ./cmd/lumgrd

test:
	go test ./...
