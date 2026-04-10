// Package admin contains the admin portal HTTP handlers and request signing.
package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	headerSignature = "X-WGP-Signature"
	headerTimestamp = "X-WGP-Timestamp"

	// hmacMaxAge is the window within which a signed request is accepted.
	// Requests older than this are rejected to prevent replay attacks.
	hmacMaxAge = 30 * time.Second
)

// HMACMiddleware verifies that incoming requests to the core carry a valid
// HMAC-SHA256 signature produced by the admin portal.
//
// The signed message is: timestamp + "\n" + HTTP method + "\n" + request URI.
// Both the timestamp and signature are sent as request headers.
// Requests outside the hmacMaxAge window are rejected regardless of signature
// validity, preventing replay attacks.
func HMACMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := verifyRequest(r, secret); err != nil {
				http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SignRequest adds HMAC signature headers to an outgoing request.
// Called by the admin portal before sending requests to the core API.
func SignRequest(r *http.Request, secret string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := computeHMAC(secret, ts, r.Method, r.URL.RequestURI())
	r.Header.Set(headerTimestamp, ts)
	r.Header.Set(headerSignature, sig)
}

// verifyRequest checks the signature and timestamp on an incoming request.
func verifyRequest(r *http.Request, secret string) error {
	tsStr := r.Header.Get(headerTimestamp)
	if tsStr == "" {
		return fmt.Errorf("missing %s header", headerTimestamp)
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp value")
	}

	// Reject stale or future-dated requests.
	age := time.Since(time.Unix(ts, 0))
	if age < 0 || age > hmacMaxAge {
		return fmt.Errorf("request timestamp out of acceptable window (±%s)", hmacMaxAge)
	}

	sig := r.Header.Get(headerSignature)
	if sig == "" {
		return fmt.Errorf("missing %s header", headerSignature)
	}

	expected := computeHMAC(secret, tsStr, r.Method, r.URL.RequestURI())

	// Constant-time comparison prevents timing attacks.
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// computeHMAC computes HMAC-SHA256 over: timestamp + "\n" + method + "\n" + URI.
func computeHMAC(secret, timestamp, method, uri string) string {
	message := timestamp + "\n" + method + "\n" + uri
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
