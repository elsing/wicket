package portal

import (
	"fmt"
	"net/http"
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

// formatDuration formats a duration as "Xh Ym" for display in templates.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
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
