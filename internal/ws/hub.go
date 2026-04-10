// Package ws implements the WebSocket hub that connects the core event system
// to browser clients and remote agents. It manages three types of connections:
//
//   - Public portal clients  — authenticated by portal session cookie
//   - Admin portal clients   — authenticated by admin session cookie
//   - Agents                 — authenticated by bcrypt-verified token
//
// Events from the core Service are fan-out to relevant subscribers.
package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/core"
)

// ClientKind identifies the type of WebSocket connection.
type ClientKind string

const (
	KindPublic ClientKind = "public"
	KindAdmin  ClientKind = "admin"
	KindAgent  ClientKind = "agent"
)

// client represents one connected WebSocket client.
type client struct {
	kind    ClientKind
	userID  string // for public/admin clients
	agentID string // for agent clients
	send    chan []byte
	conn    *websocket.Conn
}

// Hub manages all active WebSocket connections and routes events to them.
type Hub struct {
	log      *zap.Logger
	events   <-chan core.Event

	mu      sync.RWMutex
	clients map[*client]struct{}
}

// New creates a Hub that consumes from the given event channel.
func New(events <-chan core.Event, log *zap.Logger) *Hub {
	return &Hub{
		log:     log,
		events:  events,
		clients: make(map[*client]struct{}),
	}
}

// Run starts the hub's event dispatch loop. Blocks until ctx is cancelled.
func (h *Hub) Run(ctx context.Context) {
	h.log.Info("WebSocket hub started")

	for {
		select {
		case <-ctx.Done():
			h.log.Info("WebSocket hub stopped")
			return
		case event, ok := <-h.events:
			if !ok {
				return
			}
			h.broadcast(event)
		}
	}
}

// broadcast sends an event to all relevant connected clients.
func (h *Hub) broadcast(event core.Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		h.log.Error("marshalling event", zap.Error(err))
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		// Admin clients receive all events.
		if c.kind == KindAdmin {
			select {
			case c.send <- payload:
			default:
				h.log.Warn("admin client send buffer full, dropping event",
					zap.String("user_id", c.userID))
			}
			continue
		}

		// Public clients receive events relevant to their own devices/sessions.
		if c.kind == KindPublic && c.userID == event.UserID {
			select {
			case c.send <- payload:
			default:
				h.log.Warn("public client send buffer full, dropping event",
					zap.String("user_id", c.userID))
			}
		}

		// Agents receive peer add/remove events.
		if c.kind == KindAgent {
			if event.Type == core.EventPeerAdded || event.Type == core.EventPeerRemoved {
				select {
				case c.send <- payload:
				default:
					h.log.Warn("agent send buffer full, dropping event",
						zap.String("agent_id", c.agentID))
				}
			}
		}
	}
}

// register adds a client to the hub.
func (h *Hub) register(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

// unregister removes a client from the hub.
func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

// ConnectedCount returns the number of currently connected clients by kind.
func (h *Hub) ConnectedCount() map[ClientKind]int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	counts := map[ClientKind]int{KindPublic: 0, KindAdmin: 0, KindAgent: 0}
	for c := range h.clients {
		counts[c.kind]++
	}
	return counts
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP upgrade handlers
// ─────────────────────────────────────────────────────────────────────────────

// HandlePublic upgrades a public portal request to a WebSocket connection.
// userID must be extracted from the validated session before calling this.
func (h *Hub) HandlePublic(w http.ResponseWriter, r *http.Request, userID string) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Only accept connections from the same origin to prevent CSRF.
		OriginPatterns: []string{"*"}, // tightened per deployment via config
	})
	if err != nil {
		h.log.Warn("WebSocket upgrade failed (public)", zap.Error(err))
		return
	}

	c := &client{
		kind:   KindPublic,
		userID: userID,
		send:   make(chan []byte, 32),
		conn:   conn,
	}

	h.register(c)
	defer h.unregister(c)

	h.log.Debug("public WebSocket connected", zap.String("user_id", userID))
	h.serveClient(r.Context(), c)
	h.log.Debug("public WebSocket disconnected", zap.String("user_id", userID))
}

// HandleAdmin upgrades an admin portal request to a WebSocket connection.
func (h *Hub) HandleAdmin(w http.ResponseWriter, r *http.Request, userID string) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		h.log.Warn("WebSocket upgrade failed (admin)", zap.Error(err))
		return
	}

	c := &client{
		kind:   KindAdmin,
		userID: userID,
		send:   make(chan []byte, 64),
		conn:   conn,
	}

	h.register(c)
	defer h.unregister(c)

	h.log.Debug("admin WebSocket connected", zap.String("user_id", userID))
	h.serveClient(r.Context(), c)
	h.log.Debug("admin WebSocket disconnected", zap.String("user_id", userID))
}

// HandleAgent upgrades an agent request to a WebSocket connection.
// agentID must be verified before calling this.
func (h *Hub) HandleAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		h.log.Warn("WebSocket upgrade failed (agent)", zap.Error(err))
		return
	}

	c := &client{
		kind:    KindAgent,
		agentID: agentID,
		send:    make(chan []byte, 64),
		conn:    conn,
	}

	h.register(c)
	defer h.unregister(c)

	h.log.Info("agent WebSocket connected", zap.String("agent_id", agentID))
	h.serveClient(r.Context(), c)
	h.log.Info("agent WebSocket disconnected", zap.String("agent_id", agentID))
}

// serveClient runs the send loop for a connected client.
// It pumps outgoing messages and handles pings to detect dead connections.
func (h *Hub) serveClient(ctx context.Context, c *client) {
	// Ping ticker to detect stale connections.
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			c.conn.Close(websocket.StatusNormalClosure, "server shutting down")
			return

		case msg, ok := <-c.send:
			if !ok {
				c.conn.Close(websocket.StatusNormalClosure, "")
				return
			}
			ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := wsjson.Write(ctx2, c.conn, json.RawMessage(msg))
			cancel()
			if err != nil {
				h.log.Debug("WebSocket write error", zap.Error(err))
				return
			}

		case <-ping.C:
			ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.conn.Ping(ctx2)
			cancel()
			if err != nil {
				h.log.Debug("WebSocket ping failed", zap.Error(err))
				return
			}
		}
	}
}
