package portal

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// autoRenewVal returns the HTMX hx-vals JSON for the auto-renew toggle.
func autoRenewVal(val bool) string {
	if val {
		return `{"auto_renew":"true"}`
	}
	return `{"auto_renew":"false"}`
}

// urlEncode percent-encodes a WireGuard config string for use in a data: URI.
func urlEncode(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, " ", "%20")
	s = strings.ReplaceAll(s, "#", "%23")
	s = strings.ReplaceAll(s, "+", "%2B")
	return s
}

// formatDuration formats a duration for display. Shows ∞ for durations over a year.
func formatDuration(d time.Duration) string {
	if d >= 365*24*time.Hour {
		return "∞"
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		days := h / 24
		hrs := h % 24
		if hrs > 0 {
			return fmt.Sprintf("%dd %dh", days, hrs)
		}
		return fmt.Sprintf("%dd", days)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// noCacheHeaders wraps a handler to prevent browsers caching static assets.
// During active development this prevents stale JS/CSS being served.
func noCacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		h.ServeHTTP(w, r)
	})
}

// itoa converts an int to string for use in templates.
func itoa(n int) string {
	return strconv.Itoa(n)
}
