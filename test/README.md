# ETXTunnel Test Suite

This directory contains test files and scripts for testing ETXTunnel.

## Test Files

- `server.yaml` - Test server configuration
- `client.yaml` - Test client configuration
- `test_http_server.go` - Simple HTTP server for testing forwarding
- `test_http_server` - Compiled HTTP server binary
- `test_http_server.sh` - Script to start the test HTTP server
- `test_server.sh` - Script to start the tunnel server
- `test_client.sh` - Script to start the tunnel client
- `run_tests.sh` - Basic test suite
- `integration_test.sh` - Full integration test

## Running Tests

### Quick Test

Run the basic test suite:
```bash
./test/run_tests.sh
```

This will:
- Check if binaries exist
- Validate configuration files
- Test server and client startup
- Build test HTTP server
- Verify Go module

### Integration Test

Run the full integration test:
```bash
./test/integration_test.sh
```

This will:
1. Start test HTTP server on port 8080
2. Start tunnel server
3. Start tunnel client
4. Test connection through the tunnel
5. Show logs from all components

### Manual Testing

For manual testing, use three terminals:

**Terminal 1 - HTTP Server:**
```bash
./test/test_http_server.sh
```

**Terminal 2 - Tunnel Server:**
```bash
./test/test_server.sh
```

**Terminal 3 - Tunnel Client:**
```bash
./test/test_client.sh
```

**Terminal 4 - Test Connection:**
```bash
curl http://127.0.0.1:8888
```

## Test Configuration

The test configurations use:
- **Server**: Listens on `127.0.0.1:9999`, forwards to `127.0.0.1:8080`
- **Client**: Listens on `127.0.0.1:8888`, connects to server at `127.0.0.1:9999`
- **Protocol**: TCP over UDP (no root required)
- **Auth Token**: `test-token-12345`

## Notes

- Some protocols (ICMP, raw IP) require root privileges
- The test uses TCP over UDP which doesn't require root
- Make sure ports 8080, 8888, and 9999 are not in use
- The integration test will clean up processes on exit
