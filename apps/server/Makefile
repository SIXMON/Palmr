.PHONY: tidy build run docker

# Locally regenerate go.sum (run me once after `go install` is on PATH).
tidy:
	go mod tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/palmr-server ./cmd/server

run:
	go run ./cmd/server

docker:
	docker build -t palmr-server:dev .
