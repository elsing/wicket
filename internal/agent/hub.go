package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/wicket-vpn/wicket/internal/db"
)

// ConnectedAgent represents one live agent WebSocket connection.
type ConnectedAgent struct {
	ID      string
	Name    string
	VPNPool string
	send    chan Envelope
	conn    *websocket.Conn
}

// EventEmitter is a function that emits an event to the WebSocket hub.
type EventEmitter func(eventType, agentID string)

// Hub manages all connected agent WebSocket connections.
// It is the server-side counterpart to the agent binary.
type Hub struct {
	log     *zap.Logger
	db      *db.DB
	emitEvent EventEmitter // optional: emit events to admin WS clients

	mu     sync.RWMutex
	agents map[string]*ConnectedAgent // agentID -> connection
}

// New creates an agent Hub.
func New(database *db.DB, log *zap.Logger) *Hub {
	return &Hub{
		log:    log,
		db:     database,
		agents: make(map[string]*ConnectedAgent),
	}
}

// SetEventEmitter wires in a function to emit events to the WS hub.
func (h *Hub) SetEventEmitter(fn EventEmitter) {
	h.emitEvent = fn
}

// ConnectedIDs returns the IDs of all currently connected agents.
func (h *Hub) ConnectedIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.agents))
	for id := range h.agents {
		ids = append(ids, id)
	}
	return ids
}

// IsConnected reports whether an agent is currently connected.
func (h *Hub) IsConnected(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.agents[agentID]
	return ok
}

// SendPeerAdd sends a peer.add message to all agents assigned to the given groups.
// peer must be JSON-serialisable and decode to a PeerConfig on the agent side.
func (h *Hub) SendPeerAdd(agentIDs []string, peer interface{}) {
	msg := Envelope{
		Type:    MsgPeerAdd,
		MsgID:   newMsgID(),
		Payload: peer,
	}
	h.sendToAgents(agentIDs, msg)
}

// SendPeerRemove sends a peer.remove message to all agents assigned to the given groups.
func (h *Hub) SendPeerRemove(agentIDs []string, publicKey, deviceID string) {
	msg := Envelope{
		Type:  MsgPeerRemove,
		MsgID: newMsgID(),
		Payload: PeerRemovePayload{
			PublicKey: publicKey,
			DeviceID:  deviceID,
		},
	}
	h.sendToAgents(agentIDs, msg)
}

func (h *Hub) sendToAgents(agentIDs []string, msg Envelope) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, id := range agentIDs {
		if conn, ok := h.agents[id]; ok {
			select {
			case conn.send <- msg:
			default:
				h.log.Warn("agent send buffer full", zap.String("agent_id", id))
			}
		}
	}
}

// HandleConnect upgrades an HTTP request to a WebSocket agent connection.
// The agent must have already been authenticated (agentID verified).
func (h *Hub) HandleConnect(w http.ResponseWriter, r *http.Request, agentID string, syncPayload SyncPayload) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		h.log.Warn("agent WebSocket upgrade failed", zap.Error(err))
		return
	}

	a, err := h.db.GetAgentByID(r.Context(), agentID)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "agent not found")
		return
	}

	ca := &ConnectedAgent{
		ID:      agentID,
		Name:    a.Name,
		VPNPool: a.VPNPool,
		send:    make(chan Envelope, 64),
		conn:    conn,
	}

	h.mu.Lock()
	h.agents[agentID] = ca
	h.mu.Unlock()

	h.log.Info("agent connected", zap.String("agent", a.Name), zap.String("pool", a.VPNPool))
	if h.emitEvent != nil {
		h.emitEvent("agent.connected", agentID)
	}

	// Touch last_seen in DB
	_ = h.db.TouchAgentSeen(r.Context(), agentID)

	// Send full sync immediately
	ca.send <- Envelope{Type: MsgSync, MsgID: newMsgID(), Payload: syncPayload}

	defer func() {
		h.mu.Lock()
		delete(h.agents, agentID)
		h.mu.Unlock()
		h.log.Info("agent disconnected", zap.String("agent", a.Name))
	if h.emitEvent != nil {
		h.emitEvent("agent.disconnected", agentID)
	}
	}()

	h.serveAgent(r.Context(), ca)
}

func (h *Hub) serveAgent(ctx context.Context, ca *ConnectedAgent) {
	// Read loop — required by nhooyr.io/websocket, also processes acks/status.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			var msg Envelope
			if err := wsjson.Read(ctx, ca.conn, &msg); err != nil {
				return
			}
			h.handleAgentMessage(ca, msg)
		}
	}()

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			ca.conn.Close(websocket.StatusNormalClosure, "server shutting down")
			return
		case <-readDone:
			return
		case msg, ok := <-ca.send:
			if !ok {
				ca.conn.Close(websocket.StatusNormalClosure, "")
				return
			}
			wCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := wsjson.Write(wCtx, ca.conn, msg)
			cancel()
			if err != nil {
				h.log.Debug("agent write error", zap.String("agent", ca.Name), zap.Error(err))
				return
			}
		case <-ping.C:
			pingCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err := ca.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				h.log.Debug("agent ping timeout", zap.String("agent", ca.Name))
				return
			}
		}
	}
}

func (h *Hub) handleAgentMessage(ca *ConnectedAgent, msg Envelope) {
	switch msg.Type {
	case MsgReady:
		// Store the agent's WireGuard public key so client configs can use it
		if b, err := json.Marshal(msg.Payload); err == nil {
			var payload ReadyPayload
			if err := json.Unmarshal(b, &payload); err == nil && payload.WGPublicKey != "" {
				if err := h.db.UpdateAgentPublicKey(context.Background(), ca.ID, payload.WGPublicKey); err != nil {
					h.log.Warn("storing agent public key", zap.Error(err))
				} else {
					h.log.Info("agent ready",
						zap.String("agent", ca.Name),
						zap.String("wg_pubkey", payload.WGPublicKey[:8]+"..."),
						zap.String("hostname", payload.Hostname),
					)
				}
			}
		}
	case MsgAck:
		// Could log or track ack for reliability; for now just debug
		h.log.Debug("agent ack", zap.String("agent", ca.Name), zap.String("msg_id", msg.MsgID))
	case MsgStatus:
		h.log.Debug("agent status", zap.String("agent", ca.Name))
	case MsgError:
		h.log.Warn("agent reported error", zap.String("agent", ca.Name))
	}
}

func newMsgID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// BuildSyncPayload builds the SyncPayload for an agent from the DB.
// Contains all active peers from groups assigned to this agent.
func BuildSyncPayload(ctx context.Context, database *db.DB, agentID, wgInterface, privateKey string, listenPort int) (SyncPayload, error) {
	// Fetch agent record to get VPN pool for interface address calculation
	agentRecord, err := database.GetAgentByID(ctx, agentID)
	if err != nil {
		return SyncPayload{}, fmt.Errorf("fetching agent: %w", err)
	}
	vpnPool := agentRecord.VPNPool

	// Get all groups assigned to this agent
	groups, err := getAgentGroups(ctx, database, agentID)
	if err != nil {
		return SyncPayload{}, err
	}

	var peers []PeerConfig
	seen := make(map[string]bool)

	for _, g := range groups {
		// Get all active sessions for devices in this group
		sessions, err := database.ListActiveSessions(ctx)
		if err != nil {
			continue
		}
		for _, s := range sessions {
			dev, err := database.GetDeviceByID(ctx, s.DeviceID)
			if err != nil || dev.GroupID != g.ID || !dev.IsApproved || !dev.IsActive {
				continue
			}
			if seen[dev.PublicKey] {
				continue
			}
			seen[dev.PublicKey] = true

			// Get allowed IPs (routes) for this device
			routes, err := database.ListRoutesForDevice(ctx, dev.ID)
			allowedIPs := []string{dev.AssignedIP + "/32"}
			if err == nil {
				for _, r := range routes {
					allowedIPs = append(allowedIPs, r.CIDR)
				}
			}

			peers = append(peers, PeerConfig{
				PublicKey:  dev.PublicKey,
				AssignedIP: dev.AssignedIP + "/32",
				AllowedIPs: allowedIPs,
				DeviceID:   dev.ID,
				DeviceName: dev.Name,
			})
		}
	}

	// Compute interface address: first usable IP in pool (e.g. 10.1.0.0/24 → 10.1.0.1/24)
	interfaceAddr := ""
	if vpnPool != "" {
		if ip, ipNet, err := net.ParseCIDR(vpnPool); err == nil {
			_ = ip
			// Use .1 of the network
			networkIP := ipNet.IP.To4()
			if networkIP != nil {
				ifIP := make(net.IP, 4)
				copy(ifIP, networkIP)
				ifIP[3] = 1
				ones, _ := ipNet.Mask.Size()
				interfaceAddr = fmt.Sprintf("%s/%d", ifIP.String(), ones)
			}
		}
	}

	return SyncPayload{
		Peers:            peers,
		Interface:        wgInterface,
		ListenPort:       listenPort,
		PrivateKey:       privateKey,
		InterfaceAddress: interfaceAddr,
	}, nil
}

func getAgentGroups(ctx context.Context, database *db.DB, agentID string) ([]*db.Group, error) {
	groupAgentMap, err := database.GetGroupAgentMap(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := database.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var result []*db.Group
	for _, g := range groups {
		for _, aid := range groupAgentMap[g.ID] {
			if aid == agentID {
				result = append(result, g)
				break
			}
		}
	}
	return result, nil
}
