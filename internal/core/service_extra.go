package core

import (
	"context"

	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/wicket-vpn/wicket/internal/db"
)

// DB returns the underlying DB for admin handlers that need direct access.
// Use sparingly — prefer service methods where possible.
func (s *Service) DB() *db.DB {
	return s.db
}

// WriteAuditLog is a convenience wrapper for admin handlers.
// WriteAdminAuditLog logs an admin action with optional metadata.
func (s *Service) WriteAdminAuditLog(ctx context.Context, actorID, event, ip, metadata string) {
	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: actorID, Valid: actorID != ""},
		Event:     event,
		IPAddress: ip,
		Metadata:  metadata,
	}); err != nil {
		s.log.Warn("writing admin audit log", zap.Error(err))
	}
}

func (s *Service) WriteAuditLog(ctx context.Context, deviceID, userID, event, ip string) {
	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: userID, Valid: userID != ""},
		DeviceID:  sql.NullString{String: deviceID, Valid: deviceID != ""},
		Event:     event,
		IPAddress: ip,
	}); err != nil {
		s.log.Warn("writing audit log", zap.Error(err))
	}
}

// GetDeviceByIDForUser returns a device if it belongs to the given user.
func (s *Service) GetDeviceByIDForUser(ctx context.Context, deviceID, userID string) (*db.Device, error) {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if dev.UserID != userID {
		return nil, fmt.Errorf("device not found")
	}
	return dev, nil
}

// GenerateAgentToken generates a random plaintext token and its bcrypt hash.
// Returns (plaintext, hash, error). The plaintext is shown once; only the hash is stored.
func (s *Service) GenerateAgentToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating random token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(b)

	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing token: %w", err)
	}

	return token, string(hash), nil
}

// VerifyAgentToken checks a plaintext token against stored bcrypt hashes.
// Returns the matching agent or an error if no match is found.
func (s *Service) VerifyAgentToken(ctx context.Context, token string) (*db.Agent, error) {
	agents, err := s.db.GetActiveAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading agents: %w", err)
	}

	for _, agent := range agents {
		if err := bcrypt.CompareHashAndPassword([]byte(agent.TokenHash), []byte(token)); err == nil {
			return agent, nil
		}
	}

	return nil, fmt.Errorf("invalid agent token")
}
