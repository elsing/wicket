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
	AdminDevicesPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminSessions(w http.ResponseWriter, r *http.Request, data AdminSessionsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminSessionsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminUsers(w http.ResponseWriter, r *http.Request, data AdminUsersData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminUsersPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminGroups(w http.ResponseWriter, r *http.Request, data AdminGroupsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminGroupsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminSubnets(w http.ResponseWriter, r *http.Request, data AdminSubnetsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminSubnetsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAdminAgents(w http.ResponseWriter, r *http.Request, data AdminAgentsData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	AdminAgentsPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderAgentToken(w http.ResponseWriter, r *http.Request, agent *db.Agent, token string) {
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
