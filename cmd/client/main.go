package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/etxtunnel/etxtunnel/client"
	"github.com/etxtunnel/etxtunnel/cli"
	"github.com/etxtunnel/etxtunnel/config"
	"github.com/etxtunnel/etxtunnel/logger"
	"github.com/spf13/cobra"
)

var (
	configPath string
	interactive bool
)

var rootCmd = &cobra.Command{
	Use:   "etxtunnel-client",
	Short: "ETXTunnel Client - High-performance network tunneling client",
	Long: `ETXTunnel Client is a high-performance network tunneling client that supports
multiple tunneling protocols including TCP over UDP, ICMP, IP, TCP, and DNS.`,
	RunE: runClient,
}

func init() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "client.yaml", "Path to client configuration file")
	rootCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Enable interactive mode")
}

func runClient(cmd *cobra.Command, args []string) error {
	// Allow config file as positional argument if not provided via flag
	if configPath == "client.yaml" && len(args) > 0 {
		configPath = args[0]
	}
	
	// Load configuration
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create logger
	log := logger.NewLogger(logger.INFO)

	// Create and start client
	clt := client.NewClient(cfg, log)
	if err := clt.Start(); err != nil {
		return fmt.Errorf("failed to start client: %w", err)
	}
	defer clt.Stop()

	// Start interactive interface if requested
	if interactive {
		interactiveCLI := cli.NewInteractiveCLI(log)
		go interactiveCLI.Start()
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down...")
	return nil
}


func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
