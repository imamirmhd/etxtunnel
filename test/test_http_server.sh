#!/bin/bash
# Start test HTTP server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

PORT=${1:-8080}

echo "Starting test HTTP server on port $PORT..."
echo "Access it at: http://localhost:$PORT"
echo "Press Ctrl+C to stop"
echo ""

if [ -f "$SCRIPT_DIR/test_http_server" ]; then
    "$SCRIPT_DIR/test_http_server" "$PORT"
else
    echo "Building test HTTP server..."
    go build -o "$SCRIPT_DIR/test_http_server" "$SCRIPT_DIR/test_http_server.go"
    "$SCRIPT_DIR/test_http_server" "$PORT"
fi
