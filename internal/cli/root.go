// Package cli implements the wicket command-line interface.
// The "serve" subcommand starts the server.
// All other subcommands connect to the running server via Unix socket.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	socketPath string
)

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "wicket",
	Short: "WireGuard portal — self-hosted VPN management with OIDC SSO",
	Long: `wicket is a self-hosted WireGuard VPN management server.

Start the server:
  wicket serve --config /etc/wicket/config.yaml

Admin commands (server must be running):
  wicket session list
  wicket session revoke --id <session-id>
  wicket session extend --id <session-id> --duration 24h
  wicket device list [--pending]
  wicket device approve --id <device-id>
  wicket device reject  --id <device-id>
  wicket user list
  wicket reconcile`,
}

// Execute runs the root command. Called from main.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config",
		"/etc/wicket/config.yaml", "path to config file")
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket",
		"/var/run/wicket/core.sock", "path to core Unix socket")
}
