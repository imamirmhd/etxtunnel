.PHONY: build build-client build-server clean test install

# Build flags
LDFLAGS = -s -w
BUILD_FLAGS = -ldflags "$(LDFLAGS)"

# Binary names
CLIENT_BIN = bin/etxtunnel-client
SERVER_BIN = bin/etxtunnel-server

# Go files
CLIENT_MAIN = ./cmd/client/main.go
SERVER_MAIN = ./cmd/server/main.go

all: build

build: build-client build-server

build-client:
	@echo "Building client..."
	@mkdir -p bin
	@go build $(BUILD_FLAGS) -o $(CLIENT_BIN) $(CLIENT_MAIN)

build-server:
	@echo "Building server..."
	@mkdir -p bin
	@go build $(BUILD_FLAGS) -o $(SERVER_BIN) $(SERVER_MAIN)

clean:
	@echo "Cleaning..."
	@rm -rf bin/

test:
	@echo "Running tests..."
	@go test ./...

install: build
	@echo "Installing binaries..."
	@cp $(CLIENT_BIN) /usr/local/bin/
	@cp $(SERVER_BIN) /usr/local/bin/

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
