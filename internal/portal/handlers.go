package portal

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"go.uber.org/zap"

	qrcode "github.com/skip2/go-qrcode"

	agenthub "github.com/wicket-vpn/wicket/internal/agent"
	"github.com/wicket-vpn/wicket/internal/config"
	"github.com/wicket-vpn/wicket/internal/core"
	"github.com/wicket-vpn/wicket/internal/oidc"
	"github.com/wicket-vpn/wicket/internal/ws"
)

//go:embed static/agent/install.sh
var agentInstallScript []byte

const (
	oidcStateCookie = "wicket_oidc_state"
	oidcStateTTL    = 10 * time.Minute
)

// Handler is the public portal HTTP handler.
type Handler struct {
	svc      *core.Service
	oidc     *oidc.Provider
	sessions *SessionManager
	hub      *ws.Hub
	agentHub *agenthub.Hub
	cfg      *config.Config
	log      *zap.Logger
}

// NewHandler creates the public portal handler and wires all routes.
func NewHandler(
	svc *core.Service,
	oidcProvider *oidc.Provider,
	hub *ws.Hub,
	agHub *agenthub.Hub,
	cfg *config.Config,
	log *zap.Logger,
) http.Handler {
	secure := cfg.Server.Environment == "production"

	h := &Handler{
		svc:      svc,
		oidc:     oidcProvider,
		sessions: NewSessionManager(cfg.Public.SessionSecret, cfg.Public.SessionDuration, secure),
		hub:      hub,
		agentHub: agHub,
		cfg:      cfg,
		log:      log,
	}

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(
		cfg.Security.RateLimitRequests,
		cfg.Security.RateLimitWindow,
	))

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", noCacheHeaders(http.FileServer(http.Dir("web/public/static")))))

	// Public (unauthenticated) routes
	r.Get("/health", h.handleHealth)

	// Agent download — unauthenticated, rate-limited per IP.
	// Serves the wicket-agent binary and a ready-to-run install script.
	r.With(httprate.LimitByIP(10, time.Minute)).Get("/agent/download", h.handleAgentDownload)
	r.With(httprate.LimitByIP(10, time.Minute)).Get("/agent/install.sh", h.handleAgentInstallScript)
	r.Get("/agent/connect", h.handleAgentConnect) // token auth via Bearer header
	r.Get("/auth/login", h.handleLogin)
	r.Get("/auth/callback", h.handleCallback)
	r.Post("/auth/logout", h.handleLogout)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(h.sessions.Middleware("/auth/login", func(ctx context.Context, userID string) bool {
			dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			user, err := h.svc.DB().GetUserByID(dbCtx, userID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return true // transient DB error — don't log out
			}
			return err == nil && user != nil && user.IsActive
		}))

		r.Get("/", h.handleDashboard)
		r.Get("/ws", h.handleWebSocket)

		r.Get("/devices/new", h.handleNewDevice)
		r.Post("/devices", h.handleCreateDevice)
		r.Post("/devices/{deviceID}/auto-renew", h.handleSetAutoRenew)
		r.Post("/devices/{deviceID}/regenerate", h.handleRegenerateDevice)
		r.Delete("/devices/{deviceID}", h.handleDeleteDevice)
		r.Get("/devices/{deviceID}/qr", h.handleDeviceQR)

		r.Post("/sessions", h.handleActivateSession)
		r.Post("/sessions/group/{groupID}", h.handleActivateGroupSessions)
		r.Post("/sessions/{sessionID}/extend", h.handleExtendSession)
		r.Delete("/sessions/{sessionID}", h.handleRevokeSession)
	})

	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────────────────────────────────────

// serverError logs an internal error and returns a 500 to the client.
func (h *Handler) serverError(w http.ResponseWriter, msg string, err error) {
	h.log.Error("portal: "+msg, zap.Error(err))
	http.Error(w, msg, http.StatusInternalServerError)
}

// agentBinaryPath is where wicket-agent lives inside the container.
const agentBinaryPath = "/usr/local/bin/wicket-agent"

// handleAgentDownload serves the wicket-agent binary directly.
// Rate-limited to 10 requests/minute per IP.
func (h *Handler) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(agentBinaryPath)
	if err != nil {
		h.log.Warn("agent binary not found", zap.String("path", agentBinaryPath), zap.Error(err))
		http.Error(w, "agent binary not available", http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		h.serverError(w, "stat agent binary", err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="wicket-agent"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "wicket-agent", stat.ModTime(), f)
}

// handleAgentInstallScript serves the install script from the static folder,
// substituting __WICKET_PUBLIC_URL__ with the actual server URL.
func (h *Handler) handleAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	baseURL := h.cfg.Server.ExternalURL
	if baseURL == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		baseURL = scheme + "://" + r.Host
	}

	// Substitute the server URL placeholder
	out := strings.ReplaceAll(string(agentInstallScript), "__WICKET_PUBLIC_URL__", baseURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", `inline; filename="install-agent.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(out)) //nolint:errcheck
}

// handleAgentConnect handles WebSocket connections from remote agents.
// Agents authenticate with "Authorization: Bearer <token>" — no OIDC needed.
// Lives on the public portal so agents don't need access to the admin panel.
func (h *Handler) handleAgentConnect(w http.ResponseWriter, r *http.Request) {
	token := ""
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		token = auth[7:]
	}
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	agentRecord, err := h.svc.VerifyAgentToken(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if !agentRecord.IsActive {
		http.Error(w, "agent revoked", http.StatusForbidden)
		return
	}

	if h.agentHub == nil {
		http.Error(w, "agent hub not configured", http.StatusServiceUnavailable)
		return
	}

	syncPayload, err := agenthub.BuildSyncPayload(
		r.Context(),
		h.svc.DB(),
		agentRecord.ID,
		agentRecord.VPNPool,
		agentRecord.WGPrivateKey,
		h.svc.Config().WireGuard.ListenPort,
	)
	if err != nil {
		h.log.Warn("building agent sync payload", zap.Error(err))
	}

	h.agentHub.HandleConnect(w, r, agentRecord.ID, syncPayload)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := h.svc.Health(time.Time{})
	w.Header().Set("Content-Type", "application/json")
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC Auth flow
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := h.oidc.BeginAuth()
	if err != nil {
		h.log.Error("beginning OIDC auth", zap.Error(err))
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}

	secure := h.cfg.Server.Environment == "production"

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    state,
		Path:     "/auth",
		MaxAge:   int(oidcStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	// Preserve the next= redirect destination through the OIDC round-trip via a cookie.
	// Only accept relative paths (must start with "/" but not "//") to prevent open redirects.
	if next := r.URL.Query().Get("next"); next != "" && strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		http.SetCookie(w, &http.Cookie{
			Name:     "wicket_next",
			Value:    next,
			Path:     "/auth",
			MaxAge:   int(oidcStateTTL.Seconds()),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Always clear the state cookie — whether we succeed or fail.
	clearStateCookie := func() {
		http.SetCookie(w, &http.Cookie{
			Name: oidcStateCookie, Value: "", Path: "/auth", MaxAge: -1,
		})
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		// No state cookie — stale tab or direct navigation. Restart the flow.
		h.log.Debug("OIDC callback: no state cookie, restarting flow")
		clearStateCookie()
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	clearStateCookie()

	claims, err := h.oidc.CompleteAuth(r.Context(), r, stateCookie.Value)
	if err != nil {
		// invalid_grant usually means a stale auth code (server restarted, or
		// user clicked back and tried again). Restart the flow cleanly.
		h.log.Warn("OIDC callback: auth failed — restarting flow", zap.Error(err))
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	// Use background context so a browser redirect/cancel does not abort the DB write.
	result, err := h.svc.HandleLogin(context.Background(), claims.Sub, claims.Email, claims.Name, clientIP(r))
	if err != nil {
		h.log.Error("handling login", zap.String("email", claims.Email), zap.Error(err))
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	if err := h.sessions.Create(w, SessionData{
		UserID:  result.User.ID,
		Email:   result.User.Email,
		IsAdmin: result.User.IsAdmin,
	}); err != nil {
		h.log.Error("creating session cookie", zap.Error(err))
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	// Check for a preserved next= destination from before the OIDC round-trip.
	if nextCookie, err := r.Cookie("wicket_next"); err == nil && nextCookie.Value != "" {
		// Clear the cookie.
		http.SetCookie(w, &http.Cookie{
			Name: "wicket_next", Value: "", Path: "/auth", MaxAge: -1,
		})
		http.Redirect(w, r, nextCookie.Value, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.sessions.Clear(w)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())

	devices, err := h.svc.GetDevicesForUser(r.Context(), session.UserID)
	if err != nil {
		h.log.Error("getting devices", zap.Error(err))
		http.Error(w, "error loading devices", http.StatusInternalServerError)
		return
	}

	groups, err := h.svc.ListGroupsForUser(r.Context(), session.UserID)
	if err != nil {
		h.log.Error("getting groups", zap.Error(err))
		http.Error(w, "error loading groups", http.StatusInternalServerError)
		return
	}

	renderDashboard(w, r, DashboardData{
		Session: session,
		Devices: devices,
		Groups:  groups,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleNewDevice(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())

	groups, err := h.svc.ListGroupsForUser(r.Context(), session.UserID)
	if err != nil {
		h.serverError(w, "error loading groups", err)
		return
	}

	renderNewDevice(w, r, NewDeviceData{Session: session, Groups: groups})
}

func (h *Handler) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	groupID := r.FormValue("group_id")

	if name == "" || groupID == "" {
		renderNewDeviceError(w, r, session, "Device name and group are required.", nil)
		return
	}

	result, err := h.svc.CreateDevice(r.Context(), session.UserID, groupID, name, clientIP(r))
	if err != nil {
		h.log.Warn("creating device", zap.Error(err))
		groups, _ := h.svc.ListGroupsForUser(r.Context(), session.UserID)
		renderNewDeviceError(w, r, session, "Failed to create device. Please try again.", groups)
		return
	}

	renderConfigDownload(w, r, ConfigDownloadData{
		Session:    session,
		Device:     result.Device,
		ConfigFile: result.ConfigFile,
	})
}

func (h *Handler) handleSetAutoRenew(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	autoRenew := r.FormValue("auto_renew") == "true"
	if err := h.svc.SetDeviceAutoRenew(r.Context(), deviceID, session.UserID, autoRenew); err != nil {
		h.log.Warn("setting device auto-renew", zap.Error(err))
		http.Error(w, "failed to update device", http.StatusBadRequest)
		return
	}

	// Return updated device card for HTMX swap.
	devices, err := h.svc.GetDevicesForUser(r.Context(), session.UserID)
	if err != nil {
		h.serverError(w, "error loading device", err)
		return
	}
	for _, d := range devices {
		if d.ID == deviceID {
			renderDeviceCard(w, r, d)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleDeviceQR(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	_ = session

	configB64 := r.URL.Query().Get("c")
	if configB64 == "" {
		http.Error(w, "no config provided", http.StatusBadRequest)
		return
	}

	configBytes, err := base64.RawURLEncoding.DecodeString(configB64)
	if err != nil {
		http.Error(w, "invalid config", http.StatusBadRequest)
		return
	}

	png, err := qrcode.Encode(string(configBytes), qrcode.Medium, 256)
	if err != nil {
		h.log.Error("generating QR code", zap.Error(err))
		http.Error(w, "qr generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png) //nolint:errcheck
}

func (h *Handler) handleRegenerateDevice(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")

	result, err := h.svc.RegenerateDevice(r.Context(), deviceID, session.UserID, false)
	if err != nil {
		h.log.Warn("regenerating device", zap.Error(err))
		http.Error(w, "Failed to regenerate device config.", http.StatusInternalServerError)
		return
	}

	renderConfigDownload(w, r, ConfigDownloadData{
		Session:    session,
		Device:     result.Device,
		ConfigFile: result.ConfigFile,
	})
}

func (h *Handler) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.DeleteDevice(r.Context(), deviceID, session.UserID, clientIP(r), false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleActivateSession(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	deviceID := r.FormValue("device_id")
	if deviceID == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}

	vpnSession, err := h.svc.ActivateSession(r.Context(), deviceID, session.UserID, clientIP(r))
	if err != nil {
		h.log.Warn("activating session", zap.Error(err))
		http.Error(w, "failed to activate session", http.StatusBadRequest)
		return
	}

	devices, err := h.svc.GetDevicesForUser(r.Context(), session.UserID)
	if err != nil {
		h.serverError(w, "error loading device", err)
		return
	}
	for _, d := range devices {
		if d.ID == deviceID {
			d.ActiveSession = vpnSession
			renderDeviceCard(w, r, d)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleActivateGroupSessions(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	groupID := chi.URLParam(r, "groupID")

	if err := h.svc.ActivateGroupSessions(r.Context(), groupID, session.UserID, clientIP(r)); err != nil {
		h.log.Warn("activating group sessions", zap.Error(err))
	}

	h.handleDashboard(w, r)
}

func (h *Handler) handleExtendSession(w http.ResponseWriter, r *http.Request) {
	userSession := SessionFromContext(r.Context())
	sessionID := chi.URLParam(r, "sessionID")

	extended, err := h.svc.ExtendSession(r.Context(), sessionID, userSession.UserID, clientIP(r))
	if err != nil {
		h.log.Warn("extending session", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Return the full device card so the updated expiry and extension count render correctly
	devices, err := h.svc.GetDevicesForUser(r.Context(), userSession.UserID)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	for _, d := range devices {
		if d.ActiveSession != nil && d.ActiveSession.ID == extended.ID {
			renderDeviceCard(w, r, d)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	userSession := SessionFromContext(r.Context())
	sessionID := chi.URLParam(r, "sessionID")

	// Look up the device before revoking so we can return the updated card
	dbSession, err := h.svc.DB().GetSessionByID(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	if err := h.svc.RevokeSession(r.Context(), sessionID, userSession.UserID, clientIP(r), false); err != nil {
		h.log.Warn("revoking session", zap.Error(err))
		http.Error(w, "failed to revoke session", http.StatusBadRequest)
		return
	}

	// Return the updated device card so the UI reflects the change immediately
	devices, err := h.svc.GetDevicesForUser(r.Context(), userSession.UserID)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	for _, d := range devices {
		if d.ID == dbSession.DeviceID {
			renderDeviceCard(w, r, d)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	h.hub.HandlePublic(w, r, session.UserID)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	// X-Real-IP is set by Nginx/Traefik to the single real client IP.
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	// X-Forwarded-For may be a comma-separated chain: client, proxy1, proxy2
	// Take only the first (leftmost) value which is the original client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Fall back to direct connection IP, strip port if present.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}