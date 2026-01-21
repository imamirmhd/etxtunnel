# ETXTunnel

ETXTunnel is a high-performance network tunneling application written in Go that supports multiple tunneling protocols with advanced features including IP spoofing, load balancing, and connection management.

## Features

- **Multiple Tunneling Protocols**:
  - TCP over UDP
  - TCP over ICMP
  - TCP over IP (raw sockets)
  - TCP over TCP
  - TCP over DNS

- **Client Features**:
  - Multiple server support with load balancing
  - IP address spoofing
  - IP range blocking
  - Keepalive mechanism
  - Connection statistics and monitoring

- **Server Features**:
  - Protocol selection and configuration
  - Traffic forwarding
  - Client authentication
  - IP spoofing detection
  - Connection tracking

- **Interactive CLI**:
  - Real-time status monitoring
  - Connection statistics
  - Log viewing
  - Interactive commands

## Requirements

- Go 1.18 or higher
- Linux (for raw socket support - requires root privileges for some protocols)
- Network access for tunneling

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/imamirmhd/etxtunnel.git
cd etxtunnel

# Download dependencies
go mod download

# Build binaries
make build

# Or build individually
make build-client
make build-server
```

The binaries will be created in the `bin/` directory:
- `bin/etxtunnel-client` - Client binary
- `bin/etxtunnel-server` - Server binary

### Install System-wide

```bash
make install
```

This will copy the binaries to `/usr/local/bin/`.

## Configuration

### Client Configuration

Create a `client.yaml` file (see `example-client.yaml` for reference):

```yaml
listen_ip: "0.0.0.0"
listen_port: 8080
load_balance_algorithm: "round_robin"
blocked_ranges:
  - "10.0.0.0/8"
servers:
  - real_ip: "192.168.1.100"
    port: 9999
    source_address: "192.168.1.50"
    auth_token: "your-secret-token"
    keepalive_interval: 30
    weight: 1
```

**Configuration Options**:
- `listen_ip`: IP address to listen on for user connections
- `listen_port`: Port to listen on
- `load_balance_algorithm`: One of `round_robin`, `least_connections`, `random`, `weighted_round_robin`
- `blocked_ranges`: List of CIDR ranges to block
- `servers`: List of server configurations
  - `real_ip`: Server's real IP address
  - `port`: Server port
  - `source_address`: Fake IP for spoofing
  - `auth_token`: Authentication token (must match server)
  - `keepalive_interval`: Keepalive interval in seconds
  - `weight`: Weight for weighted round robin

### Server Configuration

Create a `server.yaml` file (see `example-server.yaml` for reference):

#### Single Client (Legacy Format - Still Supported)

```yaml
protocol: "tcp_over_udp"
client_real_ip: "192.168.1.50"
client_fake_ip: "192.168.1.51"
auth_token: "your-secret-token"
port: 9999
forward_destination_ip: "127.0.0.1"
forward_destination_port: 80
```

#### Multiple Clients (Recommended)

```yaml
protocol: "tcp_over_udp"
port: 9999
forward_destination_ip: "127.0.0.1"      # Default for all clients
forward_destination_port: 80              # Default for all clients

clients:
  - real_ip: "192.168.1.50"
    fake_ip: "192.168.1.51"
    auth_token: "client1-token"
    # Optional: per-client forward destination
    # forward_destination_ip: "127.0.0.1"
    # forward_destination_port: 8080

  - real_ip: "192.168.1.52"
    fake_ip: "192.168.1.53"
    auth_token: "client2-token"
    forward_destination_ip: "127.0.0.1"
    forward_destination_port: 8080
```

**Configuration Options**:
- `protocol`: One of `tcp_over_udp`, `tcp_over_icmp`, `tcp_over_ip`, `tcp_over_tcp`, `tcp_over_dns`
- `port`: Port to listen on (not applicable for ICMP)
- `forward_destination_ip`: Default IP to forward traffic to (can be overridden per-client)
- `forward_destination_port`: Default port to forward traffic to (can be overridden per-client)
- `clients`: Array of client configurations (recommended)
  - `real_ip`: Expected real IP of the client
  - `fake_ip`: Expected fake IP used by client for spoofing
  - `auth_token`: Authentication token (must match client)
  - `forward_destination_ip`: Optional per-client forward IP (overrides default)
  - `forward_destination_port`: Optional per-client forward port (overrides default)
- Legacy single-client format (deprecated but still supported):
  - `client_real_ip`: Expected real IP of the client
  - `client_fake_ip`: Expected fake IP used by client for spoofing
  - `auth_token`: Authentication token
- `dns_server`: DNS server for DNS tunneling (optional)
- `dns_domain`: Domain for DNS tunneling (optional)

**Multiple Clients Support**:
- The server can handle multiple clients simultaneously
- Each client is identified by its unique `auth_token`
- Each client can have its own forward destination
- Clients are authenticated by matching their auth token
- IP verification (real/fake) is performed per client

## Usage

### Running the Server

```bash
# Basic usage
./bin/etxtunnel-server -c server.yaml

# With interactive mode
./bin/etxtunnel-server -c server.yaml -i

# Custom config path
./bin/etxtunnel-server --config /path/to/config.yaml
```

**Note**: Some protocols (ICMP, raw IP) require root privileges:
```bash
sudo ./bin/etxtunnel-server -c server.yaml
```

### Running the Client

```bash
# Basic usage
./bin/etxtunnel-client -c client.yaml

# With interactive mode
./bin/etxtunnel-client -c client.yaml -i

# Custom config path
./bin/etxtunnel-client --config /path/to/config.yaml
```

### Interactive Mode

When running with the `-i` flag, you can use the following commands:

- `help` or `h` - Show help message
- `status` or `s` - Show current status
- `connections` or `conn` or `c` - Show active connections
- `stats` or `stat` - Show statistics
- `logs` or `l [count]` - Show recent logs (default: 10)
- `clear` or `cls` - Clear screen
- `quit` or `exit` or `q` - Exit the application

## Protocol Details

### TCP over UDP

Encapsulates TCP traffic in UDP packets. Suitable for environments where UDP is allowed but TCP might be restricted.

**Requirements**: Standard network access, no special privileges needed.

### TCP over ICMP

Encapsulates TCP traffic in ICMP echo/reply packets. Useful for bypassing firewalls that allow ICMP.

**Requirements**: Root privileges (raw sockets).

### TCP over IP

Uses raw IP sockets to send TCP data. Provides maximum control but requires root privileges.

**Requirements**: Root privileges (raw sockets).

### TCP over TCP

Standard TCP tunneling. Simple and reliable but may be blocked by firewalls.

**Requirements**: Standard network access.

### TCP over DNS

Encapsulates TCP traffic in DNS queries/responses. Useful for environments where only DNS is allowed.

**Requirements**: DNS server configuration, may require DNS server setup.

## Load Balancing

The client supports multiple load balancing algorithms:

- **Round Robin**: Distributes connections evenly across servers
- **Least Connections**: Routes to server with fewest active connections
- **Random**: Randomly selects a server
- **Weighted Round Robin**: Distributes based on server weights

## IP Spoofing

Both client and server support IP address spoofing:

- **Client**: Can send packets with a fake source IP address
- **Server**: Can detect and verify client IP addresses (real and fake)

**Note**: IP spoofing requires root privileges and may not work in all network environments.

## Security Considerations

1. **Authentication**: Always use strong, unique authentication tokens
2. **Network Security**: Be aware that tunneling can bypass network security measures
3. **Root Privileges**: Some protocols require root access - use with caution
4. **Firewall Rules**: Ensure proper firewall configuration
5. **Logging**: Monitor logs for suspicious activity

## Troubleshooting

### Connection Issues

1. **Check Configuration**: Verify IP addresses, ports, and tokens match
2. **Firewall**: Ensure ports are not blocked
3. **Privileges**: Some protocols require root/sudo
4. **Network**: Verify network connectivity

### Performance Issues

1. **Load Balancing**: Try different algorithms
2. **Server Selection**: Check server availability and load
3. **Protocol**: Some protocols have higher overhead than others
4. **Network Conditions**: Check network latency and bandwidth

### Common Errors

- **"Failed to create raw socket"**: Requires root privileges
- **"Invalid authentication token"**: Token mismatch between client and server
- **"No servers available"**: Check server configuration and availability
- **"Connection refused"**: Server not running or port blocked

## Development

### Project Structure

```
ETXTunnel/
├── cmd/
│   ├── client/        # Client entry point
│   └── server/        # Server entry point
├── client/            # Client implementation
├── server/            # Server implementation
├── protocols/         # Protocol handlers
├── config/            # Configuration management
├── logger/            # Logging and status
├── loadbalancer/      # Load balancing
├── spoofing/          # IP spoofing utilities
├── utils/             # Utility functions
└── cli/               # Interactive CLI
```

### Building

```bash
# Build all
make build

# Build client only
make build-client

# Build server only
make build-server

# Clean build artifacts
make clean

# Run tests
make test
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./client
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

## References

This project was inspired by and references concepts from:

- [udptunnel](https://github.com/astroza/udptunnel) - UDP tunneling implementation
- [icmptunnel](https://github.com/DhavalKapil/icmptunnel) - ICMP tunneling implementation
- [slipstream-rust](https://github.com/Mygod/slipstream-rust/) - DNS tunneling implementation

## Support

For issues, questions, or contributions, please open an issue on GitHub.
