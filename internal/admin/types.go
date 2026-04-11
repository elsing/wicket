package admin

import (
	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/portal"
	"github.com/wicket-vpn/wicket/internal/ws"
)

type AdminDashboardData struct {
	Session        *portal.SessionData
	PendingDevices []*db.Device
	ActiveSessions []*db.Session
	Agents         []*db.Agent
	WSCounts       map[ws.ClientKind]int
}

type AdminDevicesData struct {
	Session *portal.SessionData
	Devices []*db.Device
}

type AdminSessionsData struct {
	Session         *portal.SessionData
	Sessions        []*db.Session
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
	Subnets      []*db.Subnet
	GroupSubnets map[string][]string // groupID -> []subnetID
}

type AdminSubnetsData struct {
	Session *portal.SessionData
	Subnets []*db.Subnet
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
	Session       *portal.SessionData
	Devices       []*db.Device
	LatestMetrics map[string]*db.MetricSnapshot // deviceID -> latest snapshot
}
