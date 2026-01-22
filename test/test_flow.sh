#!/bin/bash
# Test script for ETXTunnel flow: curl => client => server => web server => server => client => curl

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== ETXTunnel Flow Test ===${NC}"
echo ""

# Check if binaries exist
if [ ! -f "../bin/etxtunnel-server" ] || [ ! -f "../bin/etxtunnel-client" ]; then
    echo -e "${RED}Error: Binaries not found. Please build first with 'make build'${NC}"
    exit 1
fi

# Kill any existing processes
echo -e "${YELLOW}[1/6]${NC} Cleaning up any existing processes..."
pkill -f etxtunnel-server || true
pkill -f etxtunnel-client || true
pkill -f "python.*web_server.py" || true
sleep 2

# Start Python web server
echo -e "${YELLOW}[2/6]${NC} Starting Python web server on port 8080..."
cd "$(dirname "$0")"
python3 web_server.py 8080 > /tmp/web_server.log 2>&1 &
WEB_SERVER_PID=$!
sleep 2

# Verify web server is running
if ! curl -s http://localhost:8080 > /dev/null; then
    echo -e "${RED}Error: Web server failed to start${NC}"
    kill $WEB_SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}✓ Web server is running${NC}"

# Start ETXTunnel server
echo -e "${YELLOW}[3/6]${NC} Starting ETXTunnel server..."
cd "$(dirname "$0")"
../bin/etxtunnel-server -c test_server.yaml > /tmp/etxtunnel_server.log 2>&1 &
SERVER_PID=$!
sleep 3

# Verify server is running
if ! pgrep -f etxtunnel-server > /dev/null; then
    echo -e "${RED}Error: ETXTunnel server failed to start${NC}"
    echo "Server log:"
    cat /tmp/etxtunnel_server.log
    kill $WEB_SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}✓ ETXTunnel server is running${NC}"

# Start ETXTunnel client
echo -e "${YELLOW}[4/6]${NC} Starting ETXTunnel client..."
cd "$(dirname "$0")"
../bin/etxtunnel-client -c test_client.yaml > /tmp/etxtunnel_client.log 2>&1 &
CLIENT_PID=$!
sleep 3

# Verify client is running
if ! pgrep -f etxtunnel-client > /dev/null; then
    echo -e "${RED}Error: ETXTunnel client failed to start${NC}"
    echo "Client log:"
    cat /tmp/etxtunnel_client.log
    kill $SERVER_PID $WEB_SERVER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}✓ ETXTunnel client is running${NC}"

# Wait a bit for connections to establish
sleep 2

# Test with curl
echo -e "${YELLOW}[5/6]${NC} Testing with curl..."
echo ""

TEST_URL="http://localhost:8081/test"
echo -e "Sending request to: ${TEST_URL}"
echo ""

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TEST_URL" || echo "CURL_ERROR")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Request successful!${NC}"
    echo ""
    echo "Response body:"
    echo "$BODY" | head -5
    echo ""
else
    echo -e "${RED}✗ Request failed (HTTP code: ${HTTP_CODE})${NC}"
    echo "Response: $RESPONSE"
    echo ""
    echo "Server log (last 20 lines):"
    tail -20 /tmp/etxtunnel_server.log
    echo ""
    echo "Client log (last 20 lines):"
    tail -20 /tmp/etxtunnel_client.log
fi

# Cleanup
echo -e "${YELLOW}[6/6]${NC} Cleaning up..."
kill $CLIENT_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
kill $WEB_SERVER_PID 2>/dev/null || true
sleep 1

if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo -e "${GREEN}=== Test completed successfully! ===${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}=== Test failed ===${NC}"
    exit 1
fi
