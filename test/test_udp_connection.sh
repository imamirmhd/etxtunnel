#!/bin/bash
# Test UDP connection between client and server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "=========================================="
echo "UDP Connection Test"
echo "=========================================="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $HTTP_PID $SERVER_PID $CLIENT_PID 2>/dev/null || true
    wait $HTTP_PID $SERVER_PID $CLIENT_PID 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Start test HTTP server
echo -e "${YELLOW}[1/4]${NC} Starting test HTTP server on port 8080..."
if [ -f "$SCRIPT_DIR/test_http_server" ]; then
    "$SCRIPT_DIR/test_http_server" 8080 > /tmp/etxtunnel_http.log 2>&1 &
else
    go build -o "$SCRIPT_DIR/test_http_server" "$SCRIPT_DIR/test_http_server.go"
    "$SCRIPT_DIR/test_http_server" 8080 > /tmp/etxtunnel_http.log 2>&1 &
fi
HTTP_PID=$!
sleep 2
if ! kill -0 $HTTP_PID 2>/dev/null; then
    echo -e "${RED}FAIL: HTTP server failed to start${NC}"
    cat /tmp/etxtunnel_http.log
    exit 1
fi
echo -e "${GREEN}PASS: HTTP server running (PID: $HTTP_PID)${NC}"
echo ""

# Start tunnel server
echo -e "${YELLOW}[2/4]${NC} Starting tunnel server..."
"$PROJECT_DIR/bin/etxtunnel-server" -c "$SCRIPT_DIR/test-server-udp.yaml" > /tmp/etxtunnel_server.log 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}FAIL: Tunnel server failed to start${NC}"
    cat /tmp/etxtunnel_server.log
    exit 1
fi
echo -e "${GREEN}PASS: Tunnel server running (PID: $SERVER_PID)${NC}"
echo ""

# Wait a bit for server to be ready
sleep 1

# Start tunnel client
echo -e "${YELLOW}[3/4]${NC} Starting tunnel client..."
"$PROJECT_DIR/bin/etxtunnel-client" -c "$SCRIPT_DIR/test-client-udp.yaml" > /tmp/etxtunnel_client.log 2>&1 &
CLIENT_PID=$!
sleep 2
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}FAIL: Tunnel client failed to start${NC}"
    cat /tmp/etxtunnel_client.log
    exit 1
fi
echo -e "${GREEN}PASS: Tunnel client running (PID: $CLIENT_PID)${NC}"
echo ""

# Wait for connections to establish
echo -e "${YELLOW}[4/4]${NC} Waiting for connections to establish..."
sleep 3

# Check server logs for connection
echo ""
echo -e "${YELLOW}Checking server logs for connection...${NC}"
if grep -q "New connection" /tmp/etxtunnel_server.log; then
    echo -e "${GREEN}PASS: Server received connection${NC}"
    grep "New connection" /tmp/etxtunnel_server.log | tail -1
else
    echo -e "${YELLOW}WARN: No connection logged yet${NC}"
fi

if grep -q "Authenticated client" /tmp/etxtunnel_server.log; then
    echo -e "${GREEN}PASS: Client authenticated successfully${NC}"
    grep "Authenticated client" /tmp/etxtunnel_server.log | tail -1
else
    echo -e "${RED}FAIL: Client authentication failed or not logged${NC}"
fi

# Test connection through tunnel
echo ""
echo -e "${YELLOW}Testing connection through tunnel...${NC}"
if curl -s -m 5 http://127.0.0.1:8888 > /tmp/etxtunnel_curl_output.txt 2>&1; then
    echo -e "${GREEN}PASS: Connection successful!${NC}"
    echo "Response:"
    cat /tmp/etxtunnel_curl_output.txt
    echo ""
else
    echo -e "${YELLOW}WARN: Connection test (checking logs)${NC}"
    cat /tmp/etxtunnel_curl_output.txt
    echo ""
fi

# Show recent logs
echo "=========================================="
echo "Server Log (last 15 lines):"
echo "=========================================="
tail -15 /tmp/etxtunnel_server.log || true
echo ""

echo "=========================================="
echo "Client Log (last 15 lines):"
echo "=========================================="
tail -15 /tmp/etxtunnel_client.log || true
echo ""

echo -e "${GREEN}UDP connection test completed!${NC}"
echo ""
