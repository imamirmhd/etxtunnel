package loadbalancer

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/etxtunnel/etxtunnel/config"
)

// LoadBalancer distributes connections across servers
type LoadBalancer struct {
	servers          []config.ServerConfig
	algorithm        config.LoadBalanceAlgorithm
	currentIndex     int
	connectionCounts map[string]int
	mu               sync.RWMutex
	rng              *rand.Rand
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(servers []config.ServerConfig, algorithm config.LoadBalanceAlgorithm) *LoadBalancer {
	return &LoadBalancer{
		servers:          servers,
		algorithm:        algorithm,
		connectionCounts: make(map[string]int),
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GetServer returns the next server based on the load balancing algorithm
func (lb *LoadBalancer) GetServer(connectionID string) *config.ServerConfig {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if len(lb.servers) == 0 {
		return nil
	}

	var selected *config.ServerConfig

	switch lb.algorithm {
	case config.RoundRobin:
		selected = &lb.servers[lb.currentIndex]
		lb.currentIndex = (lb.currentIndex + 1) % len(lb.servers)

	case config.Random:
		idx := lb.rng.Intn(len(lb.servers))
		selected = &lb.servers[idx]

	case config.LeastConnections:
		minConnections := -1
		candidates := []int{}

		for i := range lb.servers {
			serverID := lb.getServerID(i)
			count := lb.connectionCounts[serverID]

			if minConnections == -1 || count < minConnections {
				minConnections = count
				candidates = []int{i}
			} else if count == minConnections {
				candidates = append(candidates, i)
			}
		}

		if len(candidates) > 0 {
			idx := candidates[lb.rng.Intn(len(candidates))]
			selected = &lb.servers[idx]
			if connectionID != "" {
				serverID := lb.getServerID(idx)
				lb.connectionCounts[serverID]++
			}
		}

	case config.WeightedRoundRobin:
		totalWeight := 0
		for i := range lb.servers {
			weight := lb.servers[i].Weight
			if weight <= 0 {
				weight = 1
			}
			totalWeight += weight
		}

		if totalWeight > 0 {
			r := lb.rng.Intn(totalWeight)
			cumulative := 0
			for i := range lb.servers {
				weight := lb.servers[i].Weight
				if weight <= 0 {
					weight = 1
				}
				cumulative += weight
				if r < cumulative {
					selected = &lb.servers[i]
					break
				}
			}
		}
	}

	if selected == nil {
		selected = &lb.servers[0]
	}

	return selected
}

// ReleaseConnection releases a connection from a server
func (lb *LoadBalancer) ReleaseConnection(server *config.ServerConfig) {
	if lb.algorithm != config.LeastConnections {
		return
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i := range lb.servers {
		if lb.servers[i].RealIP == server.RealIP && lb.servers[i].Port == server.Port {
			serverID := lb.getServerID(i)
			if lb.connectionCounts[serverID] > 0 {
				lb.connectionCounts[serverID]--
			}
			break
		}
	}
}

// UpdateServers updates the server list
func (lb *LoadBalancer) UpdateServers(servers []config.ServerConfig) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.servers = servers
	if lb.currentIndex >= len(lb.servers) {
		lb.currentIndex = 0
	}
}

// getServerID generates a unique ID for a server
func (lb *LoadBalancer) getServerID(index int) string {
	if index < 0 || index >= len(lb.servers) {
		return ""
	}
	return fmt.Sprintf("%s:%d", lb.servers[index].RealIP, lb.servers[index].Port)
}
