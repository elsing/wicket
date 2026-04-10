// Package portal contains the public-facing HTTP portal handlers and
// session management. Sessions are stored as signed cookies — no server-side
// session store is required.
package portal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "wicket_sess"

type contextKey string

const ctxKeySession contextKey = "session"

// SessionData is the payload stored in the signed session cookie.
// Keep this small — it is serialised into every cookie.
type SessionData struct {
	UserID    string    `json:"uid"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"adm,omitempty"`
	CreatedAt time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// IsValid reports whether the session has not yet expired.
func (s *SessionData) IsValid() bool {
	return time.Now().Before(s.ExpiresAt)
}

// SessionManager creates, reads, and clears signed session cookies.
// The cookie payload is base64(JSON) + "." + HMAC-SHA256 signature.
// No session state is kept server-side.
type SessionManager struct {
	secret []byte
	ttl    time.Duration
	// secure controls whether the Secure flag is set on cookies.
	// Must be true in production (HTTPS). Can be false in development.
	secure bool
}

// NewSessionManager creates a SessionManager.
// secret must be at least 32 bytes. ttl is the session lifetime.
func NewSessionManager(secret string, ttl time.Duration, secure bool) *SessionManager {
	return &SessionManager{
		secret: []byte(secret),
		ttl:    ttl,
		secure: secure,
	}
}

// Create builds a signed session cookie and writes it to the response.
func (sm *SessionManager) Create(w http.ResponseWriter, data SessionData) error {
	now := time.Now().UTC()
	data.CreatedAt = now
	data.ExpiresAt = now.Add(sm.ttl)

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling session data: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := sm.sign(encoded)
	value := encoded + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sm.ttl.Seconds()),
		HttpOnly: true,         // not accessible via JavaScript
		Secure:   sm.secure,   // HTTPS only in production
		SameSite: http.SameSiteLaxMode, // protects against CSRF on navigations
	})

	return nil
}

// Read validates and parses the session cookie from the request.
// Returns ErrNoSession if no cookie is present.
// Returns ErrInvalidSession if the signature is wrong or the payload is malformed.
// Returns ErrSessionExpired if the session has expired.
func (sm *SessionManager) Read(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ErrNoSession
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidSession
	}
	encoded, sig := parts[0], parts[1]

	// Constant-time comparison prevents timing-based signature forgery.
	expected := sm.sign(encoded)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, ErrInvalidSession
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidSession
	}

	var data SessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, ErrInvalidSession
	}

	if !data.IsValid() {
		return nil, ErrSessionExpired
	}

	return &data, nil
}

// Clear deletes the session cookie.
func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Middleware validates the session cookie on each request.
// On success, the SessionData is injected into the request context.
// On failure, the user is redirected to loginPath.
func (sm *SessionManager) Middleware(loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sm.Read(r)
			if err != nil {
				// Clear any stale/invalid cookie before redirecting.
				sm.Clear(w)
				redirectURL := loginPath
				if r.URL.RequestURI() != "/" {
					redirectURL += "?next=" + base64.RawURLEncoding.EncodeToString(
						[]byte(r.URL.RequestURI()),
					)
				}
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeySession, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin is middleware that rejects requests from non-admin users.
// Must be used after the session Middleware.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := SessionFromContext(r.Context())
		if session == nil || !session.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SessionFromContext retrieves the SessionData from the request context.
// Returns nil if no session is present (i.e. on unauthenticated routes).
func SessionFromContext(ctx context.Context) *SessionData {
	s, _ := ctx.Value(ctxKeySession).(*SessionData)
	return s
}

// sign computes an HMAC-SHA256 signature for the given data string.
func (sm *SessionManager) sign(data string) string {
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Sentinel errors returned by Read.
var (
	ErrNoSession      = errors.New("no session cookie present")
	ErrInvalidSession = errors.New("session cookie signature invalid or malformed")
	ErrSessionExpired = errors.New("session cookie has expired")
)
