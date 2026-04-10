package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"golang.org/x/crypto/bcrypt"

	"github.com/wicket-vpn/wicket/internal/config"
	"github.com/wicket-vpn/wicket/internal/core"
	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/oidc"
	"github.com/wicket-vpn/wicket/internal/portal"
	"github.com/wicket-vpn/wicket/internal/ws"
)

const (
	adminOIDCStateCookie = "wicket_admin_state"
	adminOIDCStateTTL    = 10 * time.Minute
)

// Handler is the admin portal HTTP handler.
type Handler struct {
	svc      *core.Service
	oidc     *oidc.Provider
	sessions *portal.SessionManager
	hub      *ws.Hub
	cfg      *config.Config
	log      *zap.Logger
}

// NewHandler creates the admin portal handler and wires all routes.
// The admin portal has its own independent OIDC login flow so it works
// on a separate port without relying on cookie sharing.
func NewHandler(
	svc *core.Service,
	oidcProvider *oidc.Provider,
	hub *ws.Hub,
	cfg *config.Config,
	log *zap.Logger,
) http.Handler {
	secure := cfg.Server.Environment == "production"

	h := &Handler{
		svc:      svc,
		oidc:     oidcProvider,
		sessions: portal.NewSessionManager(cfg.Admin.SessionSecret, cfg.Public.SessionDuration, secure),
		hub:      hub,
		cfg:      cfg,
		log:      log,
	}

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Handle("/static/*", http.StripPrefix("/static/", noCacheHeaders(http.FileServer(http.Dir("web/admin/static")))))

	// Health — unauthenticated
	r.Get("/health", h.handleHealth)

	// Auth routes — OIDC and local fallback
	r.Get("/auth/login", h.handleLoginPage)
	r.Get("/auth/sso", h.handleSSO)
	r.Get("/auth/callback", h.handleCallback)
	r.Post("/auth/local", h.handleLocalLogin)
	r.Post("/auth/logout", h.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(h.sessions.Middleware("/auth/login"))
		r.Use(portal.RequireAdmin)

		r.Get("/", h.handleDashboard)
		r.Get("/dashboard/fragment", h.handleDashboardFragment)
		r.Get("/ws", h.handleWebSocket)

		r.Get("/devices", h.handleDevices)
		r.Get("/devices/pending", h.handlePendingDevices)
		r.Post("/devices/{deviceID}/approve", h.handleApproveDevice)
		r.Post("/devices/{deviceID}/reject", h.handleRejectDevice)
		r.Post("/devices/{deviceID}/disable", h.handleDisableDevice)
		r.Post("/devices/{deviceID}/enable", h.handleEnableDevice)
		r.Delete("/devices/{deviceID}", h.handleDeleteDevice)

		r.Get("/sessions", h.handleSessions)
		r.Post("/sessions/admin-activate/{deviceID}", h.handleAdminActivateSession)
		r.Post("/sessions/{sessionID}/revoke", h.handleRevokeSession)
		r.Post("/sessions/{sessionID}/extend", h.handleExtendSession)

		r.Get("/users", h.handleUsers)
		r.Post("/users/{userID}/toggle-admin", h.handleToggleAdmin)
		r.Post("/users/{userID}/assign-group", h.handleAssignGroup)

		r.Get("/groups", h.handleGroups)
		r.Post("/groups", h.handleCreateGroup)
		r.Delete("/groups/{groupID}", h.handleDeleteGroup)
		r.Post("/groups/{groupID}/subnets", h.handleAssignGroupSubnet)
		r.Delete("/groups/{groupID}/subnets/{subnetID}", h.handleRemoveGroupSubnet)

		r.Get("/subnets", h.handleSubnets)
		r.Post("/subnets", h.handleCreateSubnet)
		r.Delete("/subnets/{subnetID}", h.handleDeleteSubnet)

		r.Get("/agents", h.handleAgents)
		r.Post("/agents", h.handleCreateAgent)
		r.Delete("/agents/{agentID}", h.handleRevokeAgent)

		r.Get("/audit", h.handleAuditLog)
		r.Get("/metrics", h.handleMetrics)
		r.Get("/metrics/{deviceID}", h.handleDeviceMetrics)
	})

	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth — admin portal has its own OIDC flow
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	renderAdminLoginPage(w, r, r.URL.Query().Get("error"))
}

func (h *Handler) handleSSO(w http.ResponseWriter, r *http.Request) {
	authURL, state, err := h.oidc.BeginAuth()
	if err != nil {
		h.log.Error("admin: beginning OIDC auth", zap.Error(err))
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}

	secure := h.cfg.Server.Environment == "production"
	http.SetCookie(w, &http.Cookie{
		Name:     adminOIDCStateCookie,
		Value:    state,
		Path:     "/auth",
		MaxAge:   int(adminOIDCStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	clearState := func() {
		http.SetCookie(w, &http.Cookie{
			Name: adminOIDCStateCookie, Value: "", Path: "/auth", MaxAge: -1,
		})
	}

	stateCookie, err := r.Cookie(adminOIDCStateCookie)
	if err != nil {
		h.log.Debug("admin: OIDC callback no state cookie, restarting flow")
		clearState()
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	clearState()

	claims, err := h.oidc.CompleteAuth(r.Context(), r, stateCookie.Value)
	if err != nil {
		// Stale auth code (server restarted, back button, etc) — restart flow.
		h.log.Warn("admin: OIDC auth failed — restarting flow", zap.Error(err))
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	// Upsert the user — ensures they exist in the DB.
	// Use background context — browser redirects during OIDC callback cancel the request
	// context, which would abort the DB write mid-upsert.
	result, err := h.svc.HandleLogin(context.Background(), claims.Sub, claims.Email, claims.Name, clientIP(r))
	if err != nil {
		h.log.Error("admin: handling login", zap.Error(err))
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	// Only allow admin users through.
	if !result.User.IsAdmin {
		h.log.Warn("admin: non-admin login attempt", zap.String("email", claims.Email))
		http.Error(w, "forbidden: you do not have admin privileges", http.StatusForbidden)
		return
	}

	if err := h.sessions.Create(w, portal.SessionData{
		UserID:  result.User.ID,
		Email:   result.User.Email,
		IsAdmin: true,
	}); err != nil {
		h.log.Error("admin: creating session cookie", zap.Error(err))
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderAdminLoginPage(w, r, "Invalid request")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	account, err := h.svc.DB().GetLocalAdminByUsername(context.Background(), username)
	if err != nil {
		// Constant-time failure to prevent user enumeration
		renderAdminLoginPage(w, r, "Invalid username or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		renderAdminLoginPage(w, r, "Invalid username or password")
		return
	}

	h.log.Info("local admin login", zap.String("username", username), zap.String("ip", clientIP(r)))

	if err := h.sessions.Create(w, portal.SessionData{
		UserID:  account.ID,
		Email:   username,
		IsAdmin: true,
	}); err != nil {
		renderAdminLoginPage(w, r, "Session error")
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.sessions.Clear(w)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// ─────────────────────────────────────────────────────────────────────────────
// The rest is unchanged
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := h.svc.Health(time.Time{})
	w.Header().Set("Content-Type", "application/json")
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	pending, _ := h.svc.DB().ListPendingDevices(r.Context())
	active, _ := h.svc.DB().ListActiveSessions(r.Context())
	agents, _ := h.svc.DB().ListAgents(r.Context())
	renderAdminDashboard(w, r, AdminDashboardData{
		Session:        sess,
		PendingDevices: pending,
		ActiveSessions: active,
		Agents:         agents,
		WSCounts:       h.hub.ConnectedCount(),
	})
}

func (h *Handler) handleDashboardFragment(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	pending, _ := h.svc.DB().ListPendingDevices(r.Context())
	active, _ := h.svc.DB().ListActiveSessions(r.Context())
	agents, _ := h.svc.DB().ListAgents(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	DashboardContent(AdminDashboardData{
		Session:        sess,
		PendingDevices: pending,
		ActiveSessions: active,
		Agents:         agents,
		WSCounts:       h.hub.ConnectedCount(),
	}).Render(r.Context(), w) //nolint:errcheck
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	devices, _ := h.svc.DB().ListAllDevices(r.Context())
	renderAdminDevices(w, r, AdminDevicesData{Session: sess, Devices: devices})
}

func (h *Handler) handlePendingDevices(w http.ResponseWriter, r *http.Request) {
	devices, _ := h.svc.DB().ListPendingDevices(r.Context())
	renderPendingDevices(w, r, devices)
}

func (h *Handler) handleApproveDevice(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.ApproveDevice(r.Context(), deviceID, sess.UserID, clientIP(r)); err != nil {
		h.log.Warn("approving device", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Return updated row — device is now approved so it disappears from pending
	// and the target #dev-{id} gets deleted
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Empty response with 200 causes HTMX to delete the target element
	// since we swapped to outerHTML and return empty = element removed
	h.renderDeviceRow(w, r, deviceID)
}

func (h *Handler) handleRejectDevice(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.RejectDevice(r.Context(), deviceID, sess.UserID, clientIP(r)); err != nil {
		h.log.Warn("rejecting device", zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK) // hx-swap="delete" handles removal
}

func (h *Handler) handleDisableDevice(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.DisableDevice(r.Context(), deviceID, sess.UserID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.renderDeviceRow(w, r, deviceID)
}

func (h *Handler) handleEnableDevice(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.DB().SetDeviceActive(r.Context(), deviceID, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.svc.WriteAuditLog(r.Context(), deviceID, sess.UserID, "device.enabled", clientIP(r))
	h.renderDeviceRow(w, r, deviceID)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	sessions, _ := h.svc.DB().ListActiveSessions(r.Context())

	// Find approved+active devices that have no current session
	allDevices, _ := h.svc.DB().ListAllDevices(r.Context())
	activeDeviceIDs := make(map[string]bool)
	for _, s := range sessions {
		activeDeviceIDs[s.DeviceID] = true
	}
	var inactiveApproved []*db.Device
	for _, dev := range allDevices {
		if dev.IsApproved && dev.IsActive && !activeDeviceIDs[dev.ID] {
			inactiveApproved = append(inactiveApproved, dev)
		}
	}

	renderAdminSessions(w, r, AdminSessionsData{
		Session:         sess,
		Sessions:        sessions,
		ApprovedDevices: inactiveApproved,
	})
}

func (h *Handler) handleAdminActivateSession(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")

	dev, err := h.svc.DB().GetDeviceByID(r.Context(), deviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if _, err := h.svc.ActivateSession(r.Context(), deviceID, dev.UserID, sess.UserID+" (admin)"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	sessionID := chi.URLParam(r, "sessionID")
	if err := h.svc.RevokeSession(r.Context(), sessionID, sess.UserID, clientIP(r), true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleExtendSession(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	sessionID := chi.URLParam(r, "sessionID")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	durationStr := r.FormValue("duration")
	if durationStr == "" {
		durationStr = "24h"
	}
	d, err := time.ParseDuration(durationStr)
	if err != nil {
		http.Error(w, "invalid duration", http.StatusBadRequest)
		return
	}
	if _, err := h.svc.AdminExtendSession(r.Context(), sessionID, sess.UserID, clientIP(r), d); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	users, _ := h.svc.ListUsers(r.Context())
	groups, _ := h.svc.ListAllGroups(r.Context())
	renderAdminUsers(w, r, AdminUsersData{Session: sess, Users: users, Groups: groups})
}

func (h *Handler) handleToggleAdmin(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := h.svc.DB().GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := h.svc.DB().SetUserAdmin(r.Context(), userID, !user.IsAdmin); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Return just the updated row
	updated, err := h.svc.DB().GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	UserRow(updated).Render(r.Context(), w) //nolint:errcheck
}

func (h *Handler) handleAssignGroup(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if err := h.svc.DB().AddUserToGroup(r.Context(), userID, r.FormValue("group_id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleGroups(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	groups, _ := h.svc.ListAllGroups(r.Context())
	subnets, _ := h.svc.ListAllSubnets(r.Context())
	groupSubnets, _ := h.svc.DB().ListGroupSubnets(r.Context())
	renderAdminGroups(w, r, AdminGroupsData{
		Session:      sess,
		Groups:       groups,
		Subnets:      subnets,
		GroupSubnets: groupSubnets,
	})
}

func (h *Handler) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	d, err := time.ParseDuration(r.FormValue("session_duration"))
	if err != nil {
		d = 24 * time.Hour
	}
	if _, err := h.svc.DB().CreateGroup(r.Context(), name, r.FormValue("description"), d, nil, r.FormValue("is_public") == "true"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.handleGroups(w, r)
}

func (h *Handler) handleAssignGroupSubnet(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	groupID := chi.URLParam(r, "groupID")
	if err := h.svc.DB().AddSubnetToGroup(r.Context(), groupID, r.FormValue("subnet_id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.renderGroupCard(w, r, groupID)
}

func (h *Handler) handleRemoveGroupSubnet(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if err := h.svc.DB().RemoveSubnetFromGroup(r.Context(), groupID, chi.URLParam(r, "subnetID")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.renderGroupCard(w, r, groupID)
}

func (h *Handler) handleSubnets(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	subnets, _ := h.svc.ListAllSubnets(r.Context())
	renderAdminSubnets(w, r, AdminSubnetsData{Session: sess, Subnets: subnets})
}

func (h *Handler) handleCreateSubnet(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name, cidr := r.FormValue("name"), r.FormValue("cidr")
	if name == "" || cidr == "" {
		http.Error(w, "name and cidr are required", http.StatusBadRequest)
		return
	}
	if _, err := h.svc.DB().CreateSubnet(r.Context(), name, cidr, r.FormValue("description")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.handleSubnets(w, r)
}

func (h *Handler) handleDeleteSubnet(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DB().DeleteSubnet(r.Context(), chi.URLParam(r, "subnetID")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleAgents(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	agents, _ := h.svc.DB().ListAgents(r.Context())
	counts := h.hub.ConnectedCount()
	renderAdminAgents(w, r, AdminAgentsData{Session: sess, Agents: agents, ConnectedCount: counts[ws.KindAgent]})
}

func (h *Handler) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	token, hash, err := h.svc.GenerateAgentToken()
	if err != nil {
		h.log.Error("generating agent token", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	agent, err := h.svc.DB().CreateAgent(r.Context(), name, r.FormValue("description"), hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderAgentToken(w, r, agent, token)
}

func (h *Handler) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DB().DeactivateAgent(r.Context(), chi.URLParam(r, "agentID")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	entries, _ := h.svc.DB().ListAuditLog(r.Context(), 200)
	renderAdminAuditLog(w, r, AdminAuditData{Session: sess, Entries: entries})
}

func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	devices, _ := h.svc.DB().ListAllDevices(r.Context())
	renderAdminMetrics(w, r, AdminMetricsData{Session: sess, Devices: devices})
}

func (h *Handler) handleDeviceMetrics(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceID")
	since := time.Now().Add(-7 * 24 * time.Hour)
	snaps, err := h.svc.DB().ListMetricSnapshotsForDevice(r.Context(), deviceID, since)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snaps) //nolint:errcheck
}

func (h *Handler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	h.hub.HandleAdmin(w, r, sess.UserID)
}

// renderDeviceRow fetches a device and renders its updated table row.
func (h *Handler) renderDeviceRow(w http.ResponseWriter, r *http.Request, deviceID string) {
	devices, _ := h.svc.DB().ListAllDevices(r.Context())
	subnets, _ := h.svc.ListAllSubnets(r.Context())
	_ = subnets
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, dev := range devices {
		if dev.ID == deviceID {
			DeviceRow(dev).Render(r.Context(), w) //nolint:errcheck
			return
		}
	}
}

// renderGroupCard fetches current group data and renders just that card.
func (h *Handler) renderGroupCard(w http.ResponseWriter, r *http.Request, groupID string) {
	groups, _ := h.svc.ListAllGroups(r.Context())
	subnets, _ := h.svc.ListAllSubnets(r.Context())
	groupSubnets, _ := h.svc.DB().ListGroupSubnets(r.Context())
	renderGroupCard(w, r, AdminGroupsData{
		Groups:       groups,
		Subnets:      subnets,
		GroupSubnets: groupSubnets,
	}, groupID)
}

func (h *Handler) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	sess := portal.SessionFromContext(r.Context())
	deviceID := chi.URLParam(r, "deviceID")
	if err := h.svc.DeleteDevice(r.Context(), deviceID, sess.UserID, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	if err := h.svc.DB().DeleteGroup(r.Context(), groupID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
