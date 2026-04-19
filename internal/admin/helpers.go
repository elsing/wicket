package admin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/wicket-vpn/wicket/internal/db"
)

// firstChar returns the first character of a string, uppercased, for avatars.
func firstChar(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "?"
}

// itoa converts an int to its string representation without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if negative {
		result = "-" + result
	}
	return result
}

// eventClass returns a CSS class for an audit log event badge.
func eventClass(event string) string {
	if len(event) > 7 && event[:7] == "session" {
		return "event-session"
	}
	if len(event) > 6 && event[:6] == "device" {
		return "event-device"
	}
	if len(event) > 4 && event[:4] == "peer" {
		return "event-peer"
	}
	return "event-default"
}

// groupHasRoute checks whether a group has a specific subnet assigned.
func groupHasRoute(groupID, routeID string, groupRoutes map[string][]string) bool {
	if groupRoutes == nil {
		return false
	}
	for _, sid := range groupRoutes[groupID] {
		if sid == routeID {
			return true
		}
	}
	return false
}

// alwaysConnectedVal returns the HTMX hx-vals JSON for the always-connected toggle.
func alwaysConnectedVal(val bool) string {
	if val {
		return `{"always_connected":"true"}`
	}
	return `{"always_connected":"false"}`
}

// humanEvent converts an event key like "device.approved" to "Device Approved".
func humanEvent(event string) string {
	m := map[string]string{
		"device.created":                "Device Created",
		"device.approved":               "Device Approved",
		"device.rejected":               "Device Rejected",
		"device.disabled":               "Device Disabled",
		"device.enabled":                "Device Enabled",
		"device.always_connected.enabled":  "Always Connected On",
		"device.always_connected.disabled": "Always Connected Off",
		"session.created":               "Session Started",
		"session.extended":              "Session Extended",
		"session.revoked":               "Session Revoked",
		"session.expired":               "Session Expired",
		"peer.added":                    "Peer Added",
		"peer.removed":                  "Peer Removed",
		"user.login":                    "User Login",
		"user.admin.grant":              "Admin Granted",
		"device.deleted":                "Device Deleted",
	}
	if h, ok := m[event]; ok {
		return h
	}
	return event
}

// expiryUrgent returns true when a session expires in < 30 minutes.
func expiryUrgent(t time.Time) bool { return time.Until(t) < 30*time.Minute }

// expiryWarning returns true when a session expires in < 2 hours.
func expiryWarning(t time.Time) bool { return time.Until(t) < 2*time.Hour }

// noCacheHeaders wraps a handler to prevent browsers caching static assets.
func noCacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		h.ServeHTTP(w, r)
	})
}

// formatBytes converts a byte count to a human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// timeSince returns a human-readable "X ago" string.
func timeSince(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// groupPlural returns "s" for pluralising "device" based on count.
func groupPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// agentOptionLabel returns a short label for the agent assign dropdown.
// Called from admin.templ — gopls reports unused until templ generate runs.
func agentOptionLabel(a *db.Agent) string {
	if a.VPNPool != "" {
		return " (" + a.VPNPool + ")"
	}
	return ""
}

// agentAssigned reports whether agentID is in the assigned list.
// Called from admin.templ.
func agentAssigned(agentID string, assigned []string) bool {
	for _, id := range assigned {
		if id == agentID {
			return true
		}
	}
	return false
}
