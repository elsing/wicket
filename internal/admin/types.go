package admin

import (
	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/portal"
	"github.com/wicket-vpn/wicket/internal/ws"
)

type AdminDashboardData struct {
	Session          *portal.SessionData
	PendingDevices   []*db.Device
	ActiveSessions   []*db.Session
	Agents           []*db.Agent
	WSCounts         map[ws.ClientKind]int
	AgentsConnected  int // number of agent WebSocket connections
}

type AdminDevicesData struct {
	Session *portal.SessionData
	Devices []*db.Device
}

type AdminSessionsData struct {
	Session        *portal.SessionData
	Sessions       []*db.Session
	ApprovedDevices []*db.Device // approved devices with no active session
}

type AdminUsersData struct {
	Session *portal.SessionData
	Users   []*db.User
	Groups  []*db.Group
}

type AdminGroupsData struct {
	Session      *portal.SessionData
	Groups       []*db.Group
	Routes       []*db.Route
	Agents       []*db.Agent
	GroupRoutes  map[string][]string  // groupID -> []routeID
	GroupAgents  map[string][]string  // groupID -> []agentID
	AgentsByID   map[string]*db.Agent // agentID -> Agent
	DeviceCounts map[string]int       // groupID -> device count
}

type AdminRoutesData struct {
	Session *portal.SessionData
	Routes []*db.Route
}

type AdminAgentsData struct {
	Session        *portal.SessionData
	Agents         []*db.Agent
	ConnectedCount int
}

type AdminAuditData struct {
	Session *portal.SessionData
	Entries []*db.AuditLog
}

type AdminMetricsData struct {
	Session        *portal.SessionData
	Devices        []*db.Device
	LatestMetrics  map[string]*db.MetricSnapshot // deviceID -> latest snapshot
}

