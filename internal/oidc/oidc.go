// Package oidc wraps coreos/go-oidc to handle the full OIDC auth code flow.
// It enforces state/CSRF protection, ID token signature verification,
// audience validation, and claim extraction.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/wicket-vpn/wicket/internal/config"
)

// Claims holds the validated user claims extracted from an ID token.
type Claims struct {
	// Sub is the stable OIDC subject identifier.
	// Always use this as the primary user key — email addresses can change.
	Sub string `json:"sub"`

	Email string `json:"email"`
	Name  string `json:"name"`
}

// Provider wraps the OIDC and OAuth2 clients.
type Provider struct {
	verifier    *gooidc.IDTokenVerifier
	oauthConfig oauth2.Config
}

// New initialises an OIDC Provider by discovering the IdP's configuration.
// This contacts the OIDC discovery endpoint (.well-known/openid-configuration)
// at startup and will return an error if the IdP is unreachable.
func New(ctx context.Context, cfg *config.OIDCConfig, redirectURL string) (*Provider, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"OIDC discovery failed for issuer %q: %w\n"+
				"  → is Authentik reachable? is the issuer URL correct?",
			cfg.Issuer, err,
		)
	}

	// IDTokenVerifier enforces:
	//   - Signature valid (keys from JWKS URI, auto-refreshed)
	//   - Audience matches our client ID
	//   - Token not expired
	//   - Issuer matches
	verifier := provider.Verifier(&gooidc.Config{
		ClientID: cfg.ClientID,
	})

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       cfg.Scopes,
	}

	return &Provider{
		verifier:    verifier,
		oauthConfig: oauthConfig,
	}, nil
}

// BeginAuth returns the URL to redirect the user to for authentication,
// along with a random state token that must be stored (e.g. in a short-lived
// cookie) and verified in the callback to prevent CSRF.
func (p *Provider) BeginAuth() (authURL, state string, err error) {
	state, err = generateState()
	if err != nil {
		return "", "", fmt.Errorf("generating OIDC state: %w", err)
	}

	authURL = p.oauthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
	)

	return authURL, state, nil
}

// CompleteAuth completes the auth code flow from the callback request.
//
// It:
//  1. Validates the state parameter (CSRF protection)
//  2. Checks for error parameters returned by the IdP
//  3. Exchanges the code for tokens
//  4. Verifies the ID token signature, audience, expiry, and issuer
//  5. Extracts and validates user claims
//
// expectedState must match the value stored when BeginAuth was called.
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request, expectedState string) (*Claims, error) {
	// 1. State validation — prevents CSRF on the callback.
	state := r.URL.Query().Get("state")
	if state == "" {
		return nil, errors.New("oidc: missing state parameter in callback")
	}
	if state != expectedState {
		return nil, errors.New("oidc: state mismatch — possible CSRF attack, request rejected")
	}

	// 2. Check for errors returned by the IdP (e.g. user denied access).
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		return nil, fmt.Errorf("oidc: IdP returned error %q: %s", errParam, desc)
	}

	// 3. Extract and exchange the auth code.
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("oidc: no authorization code in callback")
	}

	// Use a separate timeout context for the token exchange so a slow/unreachable
	// IdP doesn't hang the browser indefinitely.
	exchangeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token, err := p.oauthConfig.Exchange(exchangeCtx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: exchanging auth code: %w", err)
	}

	// 4. Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("oidc: no id_token in token response — check IdP configuration")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	// 5. Extract and validate claims.
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: extracting claims: %w", err)
	}

	if claims.Sub == "" {
		return nil, errors.New("oidc: id_token missing required 'sub' claim")
	}
	if claims.Email == "" {
		return nil, errors.New("oidc: id_token missing 'email' claim — ensure 'email' scope is requested in Authentik")
	}

	return &claims, nil
}

// generateState returns a cryptographically random URL-safe base64 string.
// Used as the OAuth2 state parameter to prevent CSRF.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
