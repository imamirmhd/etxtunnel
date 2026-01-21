package config

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

// ProtocolType represents the tunneling protocol
type ProtocolType string

const (
	TCPOverUDP  ProtocolType = "tcp_over_udp"
	TCPOverICMP ProtocolType = "tcp_over_icmp"
	TCPOverIP   ProtocolType = "tcp_over_ip"
	TCPOverTCP  ProtocolType = "tcp_over_tcp"
	TCPOverDNS  ProtocolType = "tcp_over_dns"
)

// LoadBalanceAlgorithm represents load balancing strategies
type LoadBalanceAlgorithm string

const (
	RoundRobin         LoadBalanceAlgorithm = "round_robin"
	LeastConnections   LoadBalanceAlgorithm = "least_connections"
	Random             LoadBalanceAlgorithm = "random"
	WeightedRoundRobin LoadBalanceAlgorithm = "weighted_round_robin"
)

// ServerConfig represents a server configuration for the client
type ServerConfig struct {
	RealIP           string `yaml:"real_ip"`
	Port             int    `yaml:"port"`
	SourceAddress    string `yaml:"source_address"` // Fake IP for spoofing
	AuthToken        string `yaml:"auth_token"`
	KeepaliveInterval int   `yaml:"keepalive_interval"` // seconds
	Weight           int    `yaml:"weight"`            // For weighted load balancing
}

// ClientConfig represents the client configuration
type ClientConfig struct {
	ListenIP            string           `yaml:"listen_ip"`
	ListenPort          int              `yaml:"listen_port"`
	Servers             []ServerConfig   `yaml:"servers"`
	LoadBalanceAlgorithm LoadBalanceAlgorithm `yaml:"load_balance_algorithm"`
	BlockedRanges       []string         `yaml:"blocked_ranges"` // CIDR ranges
}

// ClientInfo represents a client configuration on the server side
type ClientInfo struct {
	RealIP              string `yaml:"real_ip"`
	FakeIP              string `yaml:"fake_ip"`
	AuthToken           string `yaml:"auth_token"`
	ForwardDestinationIP string `yaml:"forward_destination_ip,omitempty"`    // Per-client override
	ForwardDestinationPort int  `yaml:"forward_destination_port,omitempty"`   // Per-client override
}

// ServerProtocolConfig represents server-side protocol configuration
type ServerProtocolConfig struct {
	Protocol              ProtocolType `yaml:"protocol"`
	Port                  int          `yaml:"port"`
	ForwardDestinationIP  string       `yaml:"forward_destination_ip"`        // Default for all clients
	ForwardDestinationPort int         `yaml:"forward_destination_port"`     // Default for all clients
	DNSServer            string        `yaml:"dns_server,omitempty"`          // For DNS tunneling
	DNSDomain            string        `yaml:"dns_domain,omitempty"`         // For DNS tunneling
	
	// Support both single client (backward compatibility) and multiple clients
	ClientRealIP          string       `yaml:"client_real_ip,omitempty"`     // Deprecated: use clients[]
	ClientFakeIP          string       `yaml:"client_fake_ip,omitempty"`     // Deprecated: use clients[]
	AuthToken             string       `yaml:"auth_token,omitempty"`        // Deprecated: use clients[]
	
	// Multiple clients support
	Clients               []ClientInfo `yaml:"clients,omitempty"`
}

// LoadClientConfig loads client configuration from YAML file
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ClientConfig{
				ListenIP:            "0.0.0.0",
				ListenPort:          8080,
				LoadBalanceAlgorithm: RoundRobin,
			}, nil
		}
		return nil, err
	}

	var config ClientConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.ListenIP == "" {
		config.ListenIP = "0.0.0.0"
	}
	if config.ListenPort == 0 {
		config.ListenPort = 8080
	}
	if config.LoadBalanceAlgorithm == "" {
		config.LoadBalanceAlgorithm = RoundRobin
	}

	// Validate servers
	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("no servers configured - at least one server is required in 'servers' section")
	}

	// Validate each server
	for i, srv := range config.Servers {
		if srv.RealIP == "" {
			return nil, fmt.Errorf("server %d: 'real_ip' is required", i+1)
		}
		if srv.Port <= 0 || srv.Port > 65535 {
			return nil, fmt.Errorf("server %d: invalid port %d (must be 1-65535)", i+1, srv.Port)
		}
		if srv.AuthToken == "" {
			return nil, fmt.Errorf("server %d: 'auth_token' is required", i+1)
		}
		if srv.SourceAddress == "" {
			return nil, fmt.Errorf("server %d: 'source_address' is required", i+1)
		}
		if srv.KeepaliveInterval <= 0 {
			srv.KeepaliveInterval = 30 // Default
		}
		if srv.Weight <= 0 {
			srv.Weight = 1 // Default
		}
		config.Servers[i] = srv
	}

	return &config, nil
}

// SaveClientConfig saves client configuration to YAML file
func SaveClientConfig(config *ClientConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// LoadServerConfig loads server configuration from YAML file
func LoadServerConfig(path string) (*ServerProtocolConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config ServerProtocolConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate protocol
	switch config.Protocol {
	case TCPOverUDP, TCPOverICMP, TCPOverIP, TCPOverTCP, TCPOverDNS:
		// Valid
	default:
		return nil, fmt.Errorf("invalid protocol: %s", config.Protocol)
	}

	// Backward compatibility: convert single client config to clients array
	if len(config.Clients) == 0 {
		if config.ClientRealIP != "" || config.ClientFakeIP != "" || config.AuthToken != "" {
			// Migrate old single-client format to new format
			config.Clients = []ClientInfo{
				{
					RealIP:    config.ClientRealIP,
					FakeIP:    config.ClientFakeIP,
					AuthToken: config.AuthToken,
				},
			}
		}
	}

	// Validate clients
	if len(config.Clients) == 0 {
		return nil, fmt.Errorf("no clients configured - at least one client is required in 'clients' section (or use legacy 'client_real_ip', 'client_fake_ip', 'auth_token')")
	}

	// Validate each client
	for i, client := range config.Clients {
		if client.RealIP == "" {
			return nil, fmt.Errorf("client %d: 'real_ip' is required", i+1)
		}
		if client.FakeIP == "" {
			return nil, fmt.Errorf("client %d: 'fake_ip' is required", i+1)
		}
		if client.AuthToken == "" {
			return nil, fmt.Errorf("client %d: 'auth_token' is required", i+1)
		}
		// Use default forward destination if not specified per-client
		if client.ForwardDestinationIP == "" {
			client.ForwardDestinationIP = config.ForwardDestinationIP
		}
		if client.ForwardDestinationPort == 0 {
			client.ForwardDestinationPort = config.ForwardDestinationPort
		}
		config.Clients[i] = client
	}

	// Validate default forward destination
	if config.ForwardDestinationIP == "" {
		return nil, fmt.Errorf("'forward_destination_ip' is required")
	}
	if config.ForwardDestinationPort <= 0 || config.ForwardDestinationPort > 65535 {
		return nil, fmt.Errorf("invalid 'forward_destination_port': %d (must be 1-65535)", config.ForwardDestinationPort)
	}

	return &config, nil
}
