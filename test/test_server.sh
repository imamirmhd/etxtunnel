#!/bin/bash
# Test server startup script

echo "Starting ETXTunnel Server..."
echo "Config: test/server.yaml"
echo "Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")/.."
./bin/etxtunnel-server -c test/server.yaml -i
