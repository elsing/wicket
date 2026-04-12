package admin

import (
	"net/http"

	"github.com/wicket-vpn/wicket/internal/db"
)

func renderAdminDashboard(w http.ResponseWriter, r *http.Request, data AdminDashboardData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminDashboardPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderPendingDevices(w http.ResponseWriter, r *http.Request, devices []*db.Device) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	PendingDevicesTable(devices).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminDevices(w http.ResponseWriter, r *http.Request, data AdminDevicesData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		// Return only the tbody rows for live refresh
		DeviceTableBody(data.Devices).Render(r.Context(), w) //nolint:errcheck
		return
	}
	AdminDevicesPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminSessions(w http.ResponseWriter, r *http.Request, data AdminSessionsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		SessionTableBody(data.Sessions).Render(r.Context(), w) //nolint:errcheck
		return
	}
	AdminSessionsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminUsers(w http.ResponseWriter, r *http.Request, data AdminUsersData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminUsersPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminGroups(w http.ResponseWriter, r *http.Request, data AdminGroupsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// For HTMX requests targeting the groups list, return only the fragment
	if r.Header.Get("HX-Request") == "true" {
		GroupsList(data).Render(r.Context(), w) //nolint:errcheck
		return
	}
	AdminGroupsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderGroupCard(w http.ResponseWriter, r *http.Request, data AdminGroupsData, groupID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, g := range data.Groups {
		if g.ID == groupID {
			GroupCard(g, data.Routes, data.GroupRoutes, data.DeviceCounts[g.ID], data).Render(r.Context(), w) //nolint:errcheck
			return
		}
	}
}

func renderAdminRoutes(w http.ResponseWriter, r *http.Request, data AdminRoutesData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		RouteRows(data).Render(r.Context(), w) //nolint:errcheck
		return
	}
	AdminRoutesPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminAgents(w http.ResponseWriter, r *http.Request, data AdminAgentsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminAgentsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAgentToken(w http.ResponseWriter, _ *http.Request, agent *db.Agent, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte( //nolint:errcheck
		`<div class="alert alert-warning">` +
			`<strong>Token (shown once — copy now):</strong><br>` +
			`<code style="word-break:break-all;font-size:12px">` + token + `</code>` +
			`<br><small style="margin-top:6px;display:block">Agent: ` + agent.Name + `</small>` +
			`</div>`,
	))
}

func renderAdminAuditLog(w http.ResponseWriter, r *http.Request, data AdminAuditData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminAuditPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminMetrics(w http.ResponseWriter, r *http.Request, data AdminMetricsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminMetricsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminLoginPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminLocalLoginPage(errorMsg).Render(r.Context(), w) //nolint:errcheck
}
