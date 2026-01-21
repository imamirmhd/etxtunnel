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

// ServerProtocolConfig represents server-side protocol configuration
type ServerProtocolConfig struct {
	Protocol              ProtocolType `yaml:"protocol"`
	ClientRealIP          string       `yaml:"client_real_ip"`
	ClientFakeIP          string       `yaml:"client_fake_ip"`
	AuthToken             string       `yaml:"auth_token"`
	Port                  int          `yaml:"port"`
	ForwardDestinationIP  string       `yaml:"forward_destination_ip"`
	ForwardDestinationPort int         `yaml:"forward_destination_port"`
	DNSServer            string        `yaml:"dns_server,omitempty"`   // For DNS tunneling
	DNSDomain            string        `yaml:"dns_domain,omitempty"`    // For DNS tunneling
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

	return &config, nil
}
