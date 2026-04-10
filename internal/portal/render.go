package portal

import (
	"net/http"

	"github.com/wicket-vpn/wicket/internal/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data types passed to templates
// ─────────────────────────────────────────────────────────────────────────────

// DashboardData is the view model for the user dashboard.
type DashboardData struct {
	Session *SessionData
	Devices []*db.Device
	Groups  []*db.Group
}

// PendingDevices returns devices awaiting admin approval.
func (d *DashboardData) PendingDevices() []*db.Device {
	var out []*db.Device
	for _, dev := range d.Devices {
		if !dev.IsApproved {
			out = append(out, dev)
		}
	}
	return out
}

// DevicesForGroup returns approved devices belonging to the named group.
func (d *DashboardData) DevicesForGroup(groupName string) []*db.Device {
	var out []*db.Device
	for _, dev := range d.Devices {
		if !dev.IsApproved {
			continue
		}
		if dev.Group != nil && dev.Group.Name == groupName {
			out = append(out, dev)
		}
	}
	return out
}

// NewDeviceData is the view model for the new device form.
type NewDeviceData struct {
	Session *SessionData
	Groups  []*db.Group
	Error   string
}

// ConfigDownloadData is the view model for the one-time config download page.
type ConfigDownloadData struct {
	Session    *SessionData
	Device     *db.Device
	ConfigFile string
}

// ─────────────────────────────────────────────────────────────────────────────
// Render helpers
// ─────────────────────────────────────────────────────────────────────────────

func renderDashboard(w http.ResponseWriter, r *http.Request, data DashboardData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	DashboardPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderNewDevice(w http.ResponseWriter, r *http.Request, data NewDeviceData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	NewDevicePage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderNewDeviceError(w http.ResponseWriter, r *http.Request, session *SessionData, errMsg string, groups []*db.Group) {
	if groups == nil {
		groups = []*db.Group{}
	}
	renderNewDevice(w, r, NewDeviceData{Session: session, Groups: groups, Error: errMsg})
}

func renderConfigDownload(w http.ResponseWriter, r *http.Request, data ConfigDownloadData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ConfigDownloadPage(data).Render(r.Context(), w) //nolint:errcheck
}

func renderDeviceCard(w http.ResponseWriter, r *http.Request, device *db.Device) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	DeviceCard(device).Render(r.Context(), w) //nolint:errcheck
}

func renderSessionStatus(w http.ResponseWriter, r *http.Request, session *db.Session) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	SessionStatusFragment(session).Render(r.Context(), w) //nolint:errcheck
}
