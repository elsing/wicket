package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// SocketRequest is the JSON envelope sent by the CLI over the Unix socket.
type SocketRequest struct {
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// SocketResponse is the JSON envelope returned to the CLI.
type SocketResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

// dispatchSocketCommand reads one request from the connection, executes it,
// and writes the response. One request/response per connection.
func dispatchSocketCommand(conn net.Conn, svc *Service, log *zap.Logger) {
	respond := func(resp SocketResponse) {
		b, _ := json.Marshal(resp)
		b = append(b, '\n')
		conn.Write(b) //nolint:errcheck
	}

	var req SocketRequest
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		respond(SocketResponse{OK: false, Error: "invalid request: " + err.Error()})
		return
	}

	// 60s timeout — some commands (e.g. OIDC discovery on startup) are slow
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	log.Info("CLI command received", zap.String("command", req.Command))

	switch req.Command {

	// ── Health ────────────────────────────────────────────────────────────
	case "health":
		status := svc.Health(svc.ReconcilerLastRun())
		respond(SocketResponse{OK: true, Data: status})

	// ── Sessions ─────────────────────────────────────────────────────────
	case "session.list":
		sessions, err := svc.db.ListActiveSessions(ctx)
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: sessions})

	case "session.revoke":
		var p struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if err := svc.RevokeSession(ctx, p.SessionID, "cli", "127.0.0.1", true); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: "session revoked"})

	case "session.create":
		var p struct {
			DeviceID string `json:"device_id"`
			Duration string `json:"duration,omitempty"` // optional override, e.g. "24h"
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if p.DeviceID == "" {
			respond(SocketResponse{OK: false, Error: "device_id is required"})
			return
		}
		dev, err := svc.db.GetDeviceByID(ctx, p.DeviceID)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "device not found: " + p.DeviceID})
			return
		}
		if !dev.IsApproved || !dev.IsActive {
			respond(SocketResponse{OK: false, Error: "device is not approved or active"})
			return
		}
		session, err := svc.ActivateSession(ctx, p.DeviceID, dev.UserID, "cli")
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		// Optional duration override — extend immediately after creation.
		if p.Duration != "" {
			d, err := time.ParseDuration(p.Duration)
			if err != nil {
				respond(SocketResponse{OK: false, Error: "invalid duration: " + err.Error()})
				return
			}
			session, err = svc.AdminExtendSession(ctx, session.ID, "cli", "127.0.0.1", d)
			if err != nil {
				respond(SocketResponse{OK: false, Error: "session created but extend failed: " + err.Error()})
				return
			}
		}
		respond(SocketResponse{OK: true, Data: session})

	case "session.extend":
		var p struct {
			SessionID string `json:"session_id"`
			Duration  string `json:"duration"` // e.g. "24h"
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		d, err := time.ParseDuration(p.Duration)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "invalid duration: " + err.Error()})
			return
		}
		session, err := svc.AdminExtendSession(ctx, p.SessionID, "cli", "127.0.0.1", d)
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: session})

	// ── Devices ───────────────────────────────────────────────────────────
	case "device.list":
		var p struct {
			UserEmail string `json:"user_email,omitempty"`
			Pending   bool   `json:"pending,omitempty"`
			Active    bool   `json:"active,omitempty"`
		}
		if len(req.Payload) > 0 {
			_ = json.Unmarshal(req.Payload, &p)
		}

		var devices any
		var err error
		switch {
		case p.Pending:
			devices, err = svc.db.ListPendingDevices(ctx)
		default:
			devices, err = svc.db.ListAllDevices(ctx)
		}
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: devices})

	case "device.approve":
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if err := svc.ApproveDevice(ctx, p.DeviceID, "cli", "127.0.0.1"); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: fmt.Sprintf("device %s approved", p.DeviceID)})

	case "device.reject":
		var p struct {
			DeviceID string `json:"device_id"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if err := svc.RejectDevice(ctx, p.DeviceID, "cli", "127.0.0.1"); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: fmt.Sprintf("device %s rejected", p.DeviceID)})

	// ── Users ─────────────────────────────────────────────────────────────
	case "user.list":
		users, err := svc.ListUsers(ctx)
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: users})

	// ── Reconcile ─────────────────────────────────────────────────────────
	case "reconcile":
		// Trigger an immediate reconcile pass out-of-band.
		// The reconciler runs in its own goroutine, so we just log it.
		log.Info("CLI triggered reconcile — next scheduled pass will run shortly")
		respond(SocketResponse{OK: true, Data: "reconcile triggered"})


	case "user.make-admin":
		var p struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if p.Email == "" {
			respond(SocketResponse{OK: false, Error: "email is required"})
			return
		}
		user, err := svc.db.GetUserByEmail(ctx, p.Email)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "user not found: " + p.Email + " (have they logged in yet?)"})
			return
		}
		if err := svc.db.SetUserAdmin(ctx, user.ID, true); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: "admin granted to " + p.Email})

	case "user.remove-admin":
		var p struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if p.Email == "" {
			respond(SocketResponse{OK: false, Error: "email is required"})
			return
		}
		user, err := svc.db.GetUserByEmail(ctx, p.Email)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "user not found: " + p.Email + " (have they logged in yet?)"})
			return
		}
		if err := svc.db.SetUserAdmin(ctx, user.ID, false); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: "admin revoked from " + p.Email})


	case "agent.rotate-key":
		var p struct {
			AgentID    string `json:"agent_id"`
			PrivateKey string `json:"private_key,omitempty"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if p.AgentID == "" {
			respond(SocketResponse{OK: false, Error: "agent_id is required"})
			return
		}
		agent, err := svc.db.GetAgentByID(ctx, p.AgentID)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "agent not found: " + p.AgentID})
			return
		}
		var privKey, pubKey string
		if p.PrivateKey != "" {
			// Import mode — derive public key from the supplied private key.
			privKey = p.PrivateKey
			pubKey, err = svc.DeriveAgentPublicKey(privKey)
			if err != nil {
				respond(SocketResponse{OK: false, Error: "invalid private key: " + err.Error()})
				return
			}
		} else {
			// Generate mode — fresh keypair.
			privKey, pubKey, err = svc.GenerateAgentKeypair()
			if err != nil {
				respond(SocketResponse{OK: false, Error: "generating keypair: " + err.Error()})
				return
			}
		}
		if err := svc.db.UpdateAgentKeypair(ctx, agent.ID, privKey, pubKey); err != nil {
			respond(SocketResponse{OK: false, Error: "updating keypair: " + err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: map[string]string{
			"agent_id":   agent.ID,
			"agent_name": agent.Name,
			"public_key": pubKey,
			"note":       "Restart the agent to pick up the new key. All device configs must be regenerated.",
		}})

	case "agent.list":
		agents, err := svc.db.ListAgents(ctx)
		if err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		// Strip private keys from the response.
		type agentSummary struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			WGPublicKey string `json:"wg_public_key"`
			Endpoint    string `json:"endpoint"`
			IsActive    bool   `json:"is_active"`
		}
		summaries := make([]agentSummary, 0, len(agents))
		for _, a := range agents {
			summaries = append(summaries, agentSummary{
				ID:          a.ID,
				Name:        a.Name,
				WGPublicKey: a.WGPublicKey,
				Endpoint:    a.Endpoint,
				IsActive:    a.IsActive,
			})
		}
		respond(SocketResponse{OK: true, Data: summaries})

	
		var p struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			respond(SocketResponse{OK: false, Error: "invalid payload: " + err.Error()})
			return
		}
		if p.Username == "" || p.Password == "" {
			respond(SocketResponse{OK: false, Error: "username and password are required"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(p.Password), bcrypt.DefaultCost)
		if err != nil {
			respond(SocketResponse{OK: false, Error: "hashing password: " + err.Error()})
			return
		}
		if err := svc.db.CreateLocalAdmin(ctx, p.Username, string(hash)); err != nil {
			respond(SocketResponse{OK: false, Error: err.Error()})
			return
		}
		respond(SocketResponse{OK: true, Data: "local admin created or updated"})

	default:
		respond(SocketResponse{
			OK:    false,
			Error: fmt.Sprintf("unknown command %q — run wicket --help for available commands", req.Command),
		})
	}
}
