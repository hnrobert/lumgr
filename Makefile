BINARY_NAME=lumgrd

.PHONY: build run test build-docker run-docker stop-docker restart-docker

build:
	go build -o bin/$(BINARY_NAME) ./cmd/lumgrd

run:
	LUMGR_LISTEN=:14392 go run ./cmd/lumgrd

test:
	go test ./...

build-docker:
	docker compose build

run-docker:
	docker compose up -d

stop-docker:
	docker compose down

restart-docker: stop-docker build-docker run-docker
	docker compose logs -f
