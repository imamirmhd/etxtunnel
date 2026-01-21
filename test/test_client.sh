#!/bin/bash
# Test client startup script

echo "Starting ETXTunnel Client..."
echo "Config: test/client.yaml"
echo "Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")/.."
./bin/etxtunnel-client -c test/client.yaml -i
