package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/wicket-vpn/wicket/internal/core"
)

// ─────────────────────────────────────────────────────────────────────────────
// Socket client helpers
// ─────────────────────────────────────────────────────────────────────────────

// sendCommand sends a SocketRequest to the running server and returns the response.
func sendCommand(command string, payload any) (*core.SocketResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf(
			"connecting to socket %s: %w\n  → is the server running? (wicket serve)",
			socketPath, err,
		)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	req := core.SocketRequest{Command: command}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshalling payload: %w", err)
		}
		req.Payload = b
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending command: %w", err)
	}

	var resp core.SocketResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return &resp, nil
}

// mustOK prints the error and exits if the response is not OK.
func mustOK(resp *core.SocketResponse) {
	if !resp.OK {
		fmt.Fprintln(os.Stderr, "error:", resp.Error)
		os.Exit(1)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// session commands
// ─────────────────────────────────────────────────────────────────────────────

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage VPN sessions",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("session.list", nil)
		if err != nil {
			return err
		}
		mustOK(resp)

		b, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println(string(b))
		return nil
	},
}

var (
	sessionRevokeID string
)

var sessionRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a session by ID",
	RunE: func(cmd *cobra.Command, args []string) error {
		if sessionRevokeID == "" {
			return fmt.Errorf("--id is required")
		}
		resp, err := sendCommand("session.revoke", map[string]string{"session_id": sessionRevokeID})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Println("Session revoked.")
		return nil
	},
}

var (
	sessionExtendID       string
	sessionExtendDuration string
)

var sessionExtendCmd = &cobra.Command{
	Use:   "extend",
	Short: "Extend a session (admin override, no limit)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if sessionExtendID == "" {
			return fmt.Errorf("--id is required")
		}
		if sessionExtendDuration == "" {
			return fmt.Errorf("--duration is required (e.g. 24h)")
		}
		resp, err := sendCommand("session.extend", map[string]string{
			"session_id": sessionExtendID,
			"duration":   sessionExtendDuration,
		})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Println("Session extended.")
		return nil
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// device commands
// ─────────────────────────────────────────────────────────────────────────────

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage devices",
}

var (
	deviceListPending bool
)

var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("device.list", map[string]bool{"pending": deviceListPending})
		if err != nil {
			return err
		}
		mustOK(resp)

		b, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println(string(b))
		return nil
	},
}

var deviceApproveID string

var deviceApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending device",
	RunE: func(cmd *cobra.Command, args []string) error {
		if deviceApproveID == "" {
			return fmt.Errorf("--id is required")
		}
		resp, err := sendCommand("device.approve", map[string]string{"device_id": deviceApproveID})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Println("Device approved.")
		return nil
	},
}

var deviceRejectID string

var deviceRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject and delete a pending device",
	RunE: func(cmd *cobra.Command, args []string) error {
		if deviceRejectID == "" {
			return fmt.Errorf("--id is required")
		}
		resp, err := sendCommand("device.reject", map[string]string{"device_id": deviceRejectID})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Println("Device rejected and deleted.")
		return nil
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// user commands
// ─────────────────────────────────────────────────────────────────────────────

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("user.list", nil)
		if err != nil {
			return err
		}
		mustOK(resp)

		// Pretty-print as a table.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tEMAIL\tDISPLAY NAME\tADMIN\tACTIVE")

		// Parse the raw data as a JSON array then iterate.
		b, _ := json.Marshal(resp.Data)
		var users []struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			IsAdmin     bool   `json:"is_admin"`
			IsActive    bool   `json:"is_active"`
		}
		if err := json.Unmarshal(b, &users); err != nil {
			fmt.Println(string(b))
			return nil
		}
		for _, u := range users {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%v\n",
				u.ID[:8]+"…", u.Email, u.DisplayName, u.IsAdmin, u.IsActive)
		}
		return w.Flush()
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile command
// ─────────────────────────────────────────────────────────────────────────────

var reconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Trigger an immediate reconciliation pass",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("reconcile", nil)
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Println("Reconcile triggered.")
		return nil
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// health command
// ─────────────────────────────────────────────────────────────────────────────

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check server health",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("health", nil)
		if err != nil {
			return err
		}
		mustOK(resp)
		b, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println(string(b))
		return nil
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// init — wire everything up
// ─────────────────────────────────────────────────────────────────────────────

var (
	sessionCreateDeviceID string
	sessionCreateDuration string
)

var sessionCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new session for a device",
	Long:  "Creates an active VPN session for a device. Use 'wicket device list' to find the device ID.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if sessionCreateDeviceID == "" {
			return fmt.Errorf("--device is required")
		}
		payload := map[string]string{"device_id": sessionCreateDeviceID}
		if sessionCreateDuration != "" {
			payload["duration"] = sessionCreateDuration
		}
		resp, err := sendCommand("session.create", payload)
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Printf("✓ Session created for device %s.\n", sessionCreateDeviceID)
		return nil
	},
}

// ─────────────────────────────────────────────────────────────────────────────

func init() {
	// session subcommands
	sessionRevokeCmd.Flags().StringVar(&sessionRevokeID, "id", "", "session ID to revoke")
	sessionExtendCmd.Flags().StringVar(&sessionExtendID, "id", "", "session ID to extend")
	sessionExtendCmd.Flags().StringVar(&sessionExtendDuration, "duration", "24h", "how long to extend by (e.g. 24h, 12h)")
	sessionCreateCmd.Flags().StringVar(&sessionCreateDeviceID, "device", "", "device ID to create a session for")
	sessionCreateCmd.Flags().StringVar(&sessionCreateDuration, "duration", "", "optional duration override (e.g. 24h)")
	sessionCmd.AddCommand(sessionListCmd, sessionRevokeCmd, sessionExtendCmd, sessionCreateCmd)

	// device subcommands
	deviceListCmd.Flags().BoolVar(&deviceListPending, "pending", false, "show only pending devices")
	deviceApproveCmd.Flags().StringVar(&deviceApproveID, "id", "", "device ID to approve")
	deviceRejectCmd.Flags().StringVar(&deviceRejectID, "id", "", "device ID to reject")
	deviceCmd.AddCommand(deviceListCmd, deviceApproveCmd, deviceRejectCmd)

	// user subcommands
	userCmd.AddCommand(userListCmd)

	// root subcommands
	rootCmd.AddCommand(sessionCmd, deviceCmd, userCmd, reconcileCmd, healthCmd)
}

// ─────────────────────────────────────────────────────────────────────────────
// make-admin / remove-admin commands
// ─────────────────────────────────────────────────────────────────────────────

var makeAdminEmail string

var makeAdminCmd = &cobra.Command{
	Use:   "make-admin",
	Short: "Grant admin privileges to a user by email",
	Long:  "Use this to bootstrap the first admin user after initial login.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if makeAdminEmail == "" {
			return fmt.Errorf("--email is required")
		}
		resp, err := sendCommand("user.make-admin", map[string]string{"email": makeAdminEmail})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Printf("✓ %s is now an admin.\n", makeAdminEmail)
		return nil
	},
}

var removeAdminEmail string

var removeAdminCmd = &cobra.Command{
	Use:   "remove-admin",
	Short: "Revoke admin privileges from a user by email",
	RunE: func(cmd *cobra.Command, args []string) error {
		if removeAdminEmail == "" {
			return fmt.Errorf("--email is required")
		}
		resp, err := sendCommand("user.remove-admin", map[string]string{"email": removeAdminEmail})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Printf("✓ Admin privileges revoked from %s.\n", removeAdminEmail)
		return nil
	},
}

func init() {
	makeAdminCmd.Flags().StringVar(&makeAdminEmail, "email", "", "email address of the user to promote")
	rootCmd.AddCommand(makeAdminCmd)
	removeAdminCmd.Flags().StringVar(&removeAdminEmail, "email", "", "email address of the user to demote")
	rootCmd.AddCommand(removeAdminCmd)
}

// ─────────────────────────────────────────────────────────────────────────────
// create-local-admin command
// ─────────────────────────────────────────────────────────────────────────────

var (
	localAdminUser string
	localAdminPass string
)

var createLocalAdminCmd = &cobra.Command{
	Use:   "create-local-admin",
	Short: "Create a local admin account for emergency fallback access",
	Long:  "Creates a username/password account usable on the admin portal when OIDC is unavailable.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if localAdminUser == "" || localAdminPass == "" {
			return fmt.Errorf("--username and --password are required")
		}
		resp, err := sendCommand("admin.create-local", map[string]string{
			"username": localAdminUser,
			"password": localAdminPass,
		})
		if err != nil {
			return err
		}
		mustOK(resp)
		fmt.Printf("✓ Local admin account %q created or updated.\n", localAdminUser)
		return nil
	},
}

func init() {
	createLocalAdminCmd.Flags().StringVar(&localAdminUser, "username", "", "username for local admin account")
	createLocalAdminCmd.Flags().StringVar(&localAdminPass, "password", "", "password for local admin account")
	rootCmd.AddCommand(createLocalAdminCmd)
}

// ── Agent commands ────────────────────────────────────────────────────────────

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage remote agents",
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := sendCommand("agent.list", nil)
		if err != nil {
			return err
		}
		mustOK(resp)
		b, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println(string(b))
		return nil
	},
}

var (
	agentRotateKeyID      string
	agentRotateKeyPrivKey string
)

var agentRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the WireGuard keypair for an agent",
	Long: `Generates a new WireGuard keypair for the agent and stores it server-side.

The agent will pick up the new key automatically on its next reconnect.
WARNING: All device configs for groups using this agent must be regenerated
after rotation, as they contain the agent's public key as the endpoint.

To import an existing private key (e.g. migrating an agent already running):
  wicket agent rotate-key --id <id> --private-key <base64-private-key>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if agentRotateKeyID == "" {
			return fmt.Errorf("--id is required (use 'wicket agent list' to find the agent ID)")
		}
		payload := map[string]string{
			"agent_id": agentRotateKeyID,
		}
		if agentRotateKeyPrivKey != "" {
			payload["private_key"] = agentRotateKeyPrivKey
		}
		resp, err := sendCommand("agent.rotate-key", payload)
		if err != nil {
			return err
		}
		mustOK(resp)
		b, _ := json.MarshalIndent(resp.Data, "", "  ")
		fmt.Println(string(b))
		return nil
	},
}

func init() {
	agentRotateKeyCmd.Flags().StringVar(&agentRotateKeyID, "id", "", "agent ID to rotate the key for")
	agentRotateKeyCmd.Flags().StringVar(&agentRotateKeyPrivKey, "private-key", "", "import an existing WireGuard private key instead of generating a new one")
	agentCmd.AddCommand(agentListCmd, agentRotateKeyCmd)
	rootCmd.AddCommand(agentCmd)
}
