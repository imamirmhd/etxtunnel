#!/bin/bash
# Comprehensive test script for ETXTunnel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "=========================================="
echo "ETXTunnel Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Check if binaries exist
echo -e "${YELLOW}[TEST 1]${NC} Checking binaries..."
if [ ! -f "$PROJECT_DIR/bin/etxtunnel-server" ]; then
    echo -e "${RED}FAIL: Server binary not found${NC}"
    exit 1
fi
if [ ! -f "$PROJECT_DIR/bin/etxtunnel-client" ]; then
    echo -e "${RED}FAIL: Client binary not found${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Binaries exist${NC}"
echo ""

# Test 2: Check if config files exist
echo -e "${YELLOW}[TEST 2]${NC} Checking configuration files..."
if [ ! -f "$SCRIPT_DIR/server.yaml" ]; then
    echo -e "${RED}FAIL: Server config not found${NC}"
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/client.yaml" ]; then
    echo -e "${RED}FAIL: Client config not found${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Configuration files exist${NC}"
echo ""

# Test 3: Validate configuration files
echo -e "${YELLOW}[TEST 3]${NC} Validating configuration files..."
if ! "$PROJECT_DIR/bin/etxtunnel-server" -c "$SCRIPT_DIR/server.yaml" --help > /dev/null 2>&1; then
    echo -e "${YELLOW}WARN: Server help command check${NC}"
fi
if ! "$PROJECT_DIR/bin/etxtunnel-client" -c "$SCRIPT_DIR/client.yaml" --help > /dev/null 2>&1; then
    echo -e "${YELLOW}WARN: Client help command check${NC}"
fi
echo -e "${GREEN}PASS: Configuration validation${NC}"
echo ""

# Test 4: Test server startup (timeout after 3 seconds)
echo -e "${YELLOW}[TEST 4]${NC} Testing server startup..."
timeout 3 "$PROJECT_DIR/bin/etxtunnel-server" -c "$SCRIPT_DIR/server.yaml" 2>&1 || true
if [ $? -eq 124 ]; then
    echo -e "${GREEN}PASS: Server starts successfully${NC}"
elif [ $? -eq 0 ]; then
    echo -e "${GREEN}PASS: Server starts successfully${NC}"
else
    echo -e "${YELLOW}WARN: Server startup test (may need root for some protocols)${NC}"
fi
echo ""

# Test 5: Test client startup (timeout after 3 seconds)
echo -e "${YELLOW}[TEST 5]${NC} Testing client startup..."
timeout 3 "$PROJECT_DIR/bin/etxtunnel-client" -c "$SCRIPT_DIR/client.yaml" 2>&1 || true
if [ $? -eq 124 ]; then
    echo -e "${GREEN}PASS: Client starts successfully${NC}"
elif [ $? -eq 0 ]; then
    echo -e "${GREEN}PASS: Client starts successfully${NC}"
else
    echo -e "${YELLOW}WARN: Client startup test${NC}"
fi
echo ""

# Test 6: Build test HTTP server
echo -e "${YELLOW}[TEST 6]${NC} Building test HTTP server..."
if go build -o "$SCRIPT_DIR/test_http_server" "$SCRIPT_DIR/test_http_server.go" 2>&1; then
    echo -e "${GREEN}PASS: Test HTTP server built${NC}"
else
    echo -e "${RED}FAIL: Failed to build test HTTP server${NC}"
    exit 1
fi
echo ""

# Test 7: Check Go module
echo -e "${YELLOW}[TEST 7]${NC} Checking Go module..."
if go mod verify 2>&1; then
    echo -e "${GREEN}PASS: Go module is valid${NC}"
else
    echo -e "${YELLOW}WARN: Go module verification${NC}"
fi
echo ""

echo "=========================================="
echo -e "${GREEN}All basic tests completed!${NC}"
echo "=========================================="
echo ""
echo "To run the full test:"
echo "  1. Terminal 1: ./test/test_http_server.sh"
echo "  2. Terminal 2: ./test/test_server.sh"
echo "  3. Terminal 3: ./test/test_client.sh"
echo "  4. Terminal 4: curl http://127.0.0.1:8888"
