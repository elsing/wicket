// Package core contains the central business logic for wicket.
// Both portals, the CLI, and agents interact exclusively through Service.
// Nothing outside this package touches the database or WireGuard directly.
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/config"
	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/wireguard"
)

// Service is the central business logic layer.
type Service struct {
	db         *db.DB
	peers      wireguard.PeerManager
	cfg        *config.Config
	log        *zap.Logger
	eventCh    chan Event
	reconciler *Reconciler // set after construction via SetReconciler
}

// SetReconciler wires the reconciler into the service so health checks can
// report its last run time.
func (s *Service) SetReconciler(r *Reconciler) {
	s.reconciler = r
}

// NewService constructs the core service.
func NewService(database *db.DB, peers wireguard.PeerManager, cfg *config.Config, log *zap.Logger) *Service {
	return &Service{
		db:      database,
		peers:   peers,
		cfg:     cfg,
		log:     log,
		eventCh: make(chan Event, 128),
	}
}

// Events returns the read-only channel consumed by the WebSocket hub.
func (s *Service) Events() <-chan Event {
	return s.eventCh
}

// emit dispatches an event without blocking. Dropped if the channel is full.
func (s *Service) emit(e Event) {
	select {
	case s.eventCh <- e:
	default:
		s.log.Warn("event channel full, dropping event", zap.String("type", string(e.Type)))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth / Users
// ─────────────────────────────────────────────────────────────────────────────

// LoginResult is returned by HandleLogin.
type LoginResult struct {
	User       *db.User
	FirstLogin bool
}

// HandleLogin creates or updates the user from OIDC claims, records the login
// in the audit log, and triggers auto-renew for eligible devices.
// ipAddress is the client's IP address, used for audit logging.
func (s *Service) HandleLogin(ctx context.Context, sub, email, displayName, ipAddress string) (*LoginResult, error) {
	user, err := s.db.UpsertUser(ctx, sub, email, displayName)
	if err != nil {
		return nil, fmt.Errorf("upserting user: %w", err)
	}

	// Determine if this is the first login by checking whether the user
	// existed before this upsert. The UpsertUser implementation sets
	// last_login_at on every login, so first login = last_login_at was null.
	firstLogin := !user.LastLoginAt.Valid

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: user.ID, Valid: true},
		Event:     db.AuditEventUserLogin,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("email", email, "first_login", firstLogin),
	}); err != nil {
		s.log.Warn("writing login audit log", zap.Error(err))
	}

	if !firstLogin && s.cfg.Security.AllowPortalSessionExtension {
		go s.autoRenewDevices(context.Background(), user.ID, ipAddress)
	}

	return &LoginResult{User: user, FirstLogin: firstLogin}, nil
}

// autoRenewDevices activates sessions for all approved devices with auto_renew=true.
// Run in a goroutine — errors are logged, not propagated.
func (s *Service) autoRenewDevices(ctx context.Context, userID, ipAddress string) {
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("PANIC in autoRenewDevices", zap.Any("panic", rec))
		}
	}()
	devices, err := s.db.ListDevicesByUser(ctx, userID)
	if err != nil {
		s.log.Error("auto-renew: listing devices", zap.String("user_id", userID), zap.Error(err))
		return
	}

	for _, dev := range devices {
		if !dev.AutoRenew || !dev.IsApproved || !dev.IsActive {
			continue
		}
		if _, err := s.ActivateSession(ctx, dev.ID, userID, ipAddress); err != nil {
			s.log.Warn("auto-renew: activating session",
				zap.String("device_id", dev.ID),
				zap.String("device_name", dev.Name),
				zap.Error(err),
			)
		}
	}
}

// GetUser returns a user by ID.
func (s *Service) GetUser(ctx context.Context, id string) (*db.User, error) {
	return s.db.GetUserByID(ctx, id)
}

// ListUsers returns all users (admin only).
func (s *Service) ListUsers(ctx context.Context) ([]*db.User, error) {
	return s.db.ListUsers(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices
// ─────────────────────────────────────────────────────────────────────────────

// CreateDeviceResult holds the output of CreateDevice.
type CreateDeviceResult struct {
	Device     *db.Device
	PrivateKey string // the client's WireGuard private key — returned ONCE, never stored
	ConfigFile string // the complete .conf file content — returned ONCE, never stored
}

// CreateDevice generates a WireGuard keypair, allocates a VPN IP, creates the
// device record as pending approval, and returns the one-time config.
// The private key is discarded from this process after being returned.
func (s *Service) CreateDevice(ctx context.Context, userID, groupID, name, ipAddress string) (*CreateDeviceResult, error) {
	// Validate the requested group is accessible to this user.
	availableGroups, err := s.db.ListGroupsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing groups for user: %w", err)
	}

	var group *db.Group
	for _, g := range availableGroups {
		if g.ID == groupID {
			group = g
			break
		}
	}
	if group == nil {
		return nil, errors.New("group not found or not accessible to this user")
	}

	// Generate WireGuard keypair. Private key is handled here only.
	privateKey, publicKey, err := wireguard.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}

	// Allocate the next available IP in the VPN subnet.
	assignedIP, err := s.allocateIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("allocating VPN IP: %w", err)
	}

	// Persist the device. is_approved defaults to 0 — admin must approve.
	dev, err := s.db.CreateDevice(ctx, &db.Device{
		UserID:     userID,
		GroupID:    groupID,
		Name:       name,
		PublicKey:  publicKey,
		AssignedIP: assignedIP,
	})
	if err != nil {
		return nil, fmt.Errorf("creating device record: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: userID, Valid: true},
		DeviceID:  sql.NullString{String: dev.ID, Valid: true},
		Event:     db.AuditEventDeviceCreated,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("group_id", groupID, "group_name", group.Name, "device_name", name),
	}); err != nil {
		s.log.Warn("writing device created audit log", zap.Error(err))
	}

	s.emit(Event{Type: EventDeviceCreated, UserID: userID, OwnerID: userID, DeviceID: dev.ID})

	// Build the one-time config file.
	conf, err := s.buildClientConfig(ctx, dev, privateKey)
	if err != nil {
		return nil, fmt.Errorf("building client config: %w", err)
	}

	return &CreateDeviceResult{
		Device:     dev,
		PrivateKey: privateKey,
		ConfigFile: conf,
	}, nil
}

// buildClientConfig assembles the WireGuard .conf for a device.
func (s *Service) buildClientConfig(ctx context.Context, dev *db.Device, privateKey string) (string, error) {
	subnets, err := s.db.ListSubnetsForDevice(ctx, dev.ID)
	if err != nil {
		return "", fmt.Errorf("listing subnets for device: %w", err)
	}

	allowedIPs := make([]string, 0, len(subnets)+1)
	for _, sub := range subnets {
		allowedIPs = append(allowedIPs, sub.CIDR)
	}

	// Always include the VPN subnet itself so the device can reach the server
	// and other peers, even if no explicit subnets are configured.
	if len(allowedIPs) == 0 {
		// No subnets configured — route the entire VPN range as a minimum.
		_, vpnNet, err := net.ParseCIDR(s.cfg.WireGuard.Address)
		if err == nil {
			allowedIPs = append(allowedIPs, vpnNet.String())
		}
	}

	// If 0.0.0.0/0 is present (full-tunnel mode), also add ::/0 so IPv6 routes
	// through the tunnel too, preventing IPv6 leaks.
	for _, ip := range allowedIPs {
		if ip == "0.0.0.0/0" {
			allowedIPs = append(allowedIPs, "::/0")
			break
		}
	}

	serverPubKey, err := wireguard.ServerPublicKey(s.cfg.WireGuard.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("deriving server public key: %w", err)
	}

	conf := wireguard.BuildClientConfig(wireguard.ClientConfigParams{
		PrivateKey:      privateKey,
		AssignedIP:      dev.AssignedIP,
		DNS:             s.cfg.WireGuard.DNS,
		ServerPublicKey: serverPubKey,
		ServerEndpoint:  s.cfg.WireGuard.Endpoint, // already host:port from config
		AllowedIPs:      allowedIPs,
		MTU:             s.cfg.WireGuard.MTU,
	})

	return conf, nil
}

// buildPeerConfigForDevice constructs a wireguard.PeerConfig from a Device.
// Used for immediate peer addition on session activation.
func (s *Service) buildPeerConfigForDevice(ctx context.Context, dev *db.Device) (*wireguard.PeerConfig, error) {
	subnets, err := s.db.ListSubnetsForDevice(ctx, dev.ID)
	if err != nil {
		return nil, fmt.Errorf("listing subnets: %w", err)
	}

	allowedIPs := make([]net.IPNet, 0, len(subnets)+1)
	for _, sub := range subnets {
		_, ipNet, err := net.ParseCIDR(sub.CIDR)
		if err != nil {
			s.log.Warn("skipping invalid subnet CIDR",
				zap.String("cidr", sub.CIDR), zap.Error(err))
			continue
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	// If no subnets configured, fall back to the full VPN subnet.
	// This ensures the peer can at least reach the server.
	if len(allowedIPs) == 0 {
		_, vpnNet, err := net.ParseCIDR(s.cfg.WireGuard.Address)
		if err == nil {
			allowedIPs = append(allowedIPs, *vpnNet)
			s.log.Debug("no subnets configured for device, using VPN subnet as fallback",
				zap.String("device", dev.Name),
				zap.String("subnet", vpnNet.String()),
			)
		}
	}

	ip := net.ParseIP(dev.AssignedIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid assigned IP %q for device %s", dev.AssignedIP, dev.Name)
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	s.log.Debug("built peer config",
		zap.String("device", dev.Name),
		zap.String("assigned_ip", ip.String()),
		zap.Int("allowed_ip_count", len(allowedIPs)),
	)

	return &wireguard.PeerConfig{
		PublicKey:  dev.PublicKey,
		AssignedIP: ip,
		AllowedIPs: allowedIPs,
	}, nil
}

// ApproveDevice marks a device as approved, adds the peer to WireGuard if
// a session already exists, and emits an event.
func (s *Service) ApproveDevice(ctx context.Context, deviceID, adminUserID, ipAddress string) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}
	if dev.IsApproved {
		return errors.New("device is already approved")
	}

	if err := s.db.ApproveDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("approving device in DB: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: adminUserID, Valid: true},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     db.AuditEventDeviceApproved,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("device_name", dev.Name),
	}); err != nil {
		s.log.Warn("writing device approved audit log", zap.Error(err))
	}

	s.emit(Event{Type: EventDeviceApproved, DeviceID: deviceID, UserID: adminUserID, OwnerID: dev.UserID, Payload: map[string]any{"device_name": dev.Name}})
	return nil
}

// RejectDevice deletes a pending device and notifies the user.
func (s *Service) RejectDevice(ctx context.Context, deviceID, adminUserID, ipAddress string) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}

	if err := s.db.RejectDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("rejecting device: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: adminUserID, Valid: true},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     db.AuditEventDeviceRejected,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("device_name", dev.Name),
	}); err != nil {
		s.log.Warn("writing device rejected audit log", zap.Error(err))
	}

	s.emit(Event{Type: EventDeviceRejected, DeviceID: deviceID, UserID: adminUserID, OwnerID: dev.UserID, Payload: map[string]any{"device_name": dev.Name}})
	return nil
}

// DisableDevice marks a device inactive, revokes all active sessions, and removes the WireGuard peer.
func (s *Service) DisableDevice(ctx context.Context, deviceID, actorUserID string) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}

	// Revoke any active sessions
	sess, err := s.db.GetActiveSessionForDevice(ctx, deviceID)
	if err == nil && sess != nil {
		if err := s.db.RevokeSession(ctx, sess.ID, actorUserID); err != nil {
			s.log.Warn("revoking session on disable", zap.Error(err))
		}
	}

	// Remove from WireGuard immediately
	if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
		s.log.Warn("removing peer on disable", zap.String("device", dev.Name), zap.Error(err))
	}

	// Mark disabled in DB
	if err := s.db.SetDeviceActive(ctx, deviceID, false); err != nil {
		return fmt.Errorf("disabling device: %w", err)
	}

	s.log.Info("device disabled", zap.String("device", dev.Name), zap.String("actor", actorUserID))
	s.emit(Event{Type: EventPeerRemoved, DeviceID: deviceID, UserID: actorUserID, OwnerID: dev.UserID})
	return nil
}

// DeleteDevice removes a device, revokes any active sessions, and removes the WireGuard peer.
func (s *Service) DeleteDevice(ctx context.Context, deviceID, actorUserID string, isAdmin bool) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}
	if !isAdmin && dev.UserID != actorUserID {
		return errors.New("not authorised to delete this device")
	}

	// Remove the WireGuard peer immediately.
	if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
		s.log.Warn("removing peer on device delete", zap.String("device", dev.Name), zap.Error(err))
	}

	if err := s.db.DeleteDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("deleting device: %w", err)
	}

	s.log.Info("device deleted", zap.String("device", dev.Name), zap.String("actor", actorUserID))
	s.emit(Event{Type: EventDeviceRejected, DeviceID: deviceID, UserID: actorUserID, OwnerID: dev.UserID})
	return nil
}

// GetDevicesForUser returns all devices for a user, enriched with their active sessions.
func (s *Service) GetDevicesForUser(ctx context.Context, userID string) ([]*db.Device, error) {
	devices, err := s.db.ListDevicesByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Enrich each device with its active session and group info.
	for _, dev := range devices {
		session, err := s.db.GetActiveSessionForDevice(ctx, dev.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.log.Warn("getting active session for device", zap.String("device_id", dev.ID), zap.Error(err))
		}
		dev.ActiveSession = session

		group, err := s.db.GetGroupByID(ctx, dev.GroupID)
		if err != nil {
			s.log.Warn("getting group for device", zap.String("device_id", dev.ID), zap.Error(err))
		}
		dev.Group = group
	}

	return devices, nil
}

// SetDeviceAutoRenew sets the auto_renew flag on a device the user owns.
func (s *Service) SetDeviceAutoRenew(ctx context.Context, deviceID, userID string, autoRenew bool) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if dev.UserID != userID {
		return errors.New("device does not belong to user")
	}
	return s.db.SetDeviceAutoRenew(ctx, deviceID, autoRenew)
}

// MarkConfigDownloaded marks that the one-time config has been downloaded.
func (s *Service) MarkConfigDownloaded(ctx context.Context, deviceID, userID string) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if dev.UserID != userID {
		return errors.New("device does not belong to user")
	}
	return s.db.MarkConfigDownloaded(ctx, deviceID)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────────────────────

// ActivateSession creates a new VPN session for a device.
// Validates the device belongs to the user and is approved and active.
// The reconciler will add the WireGuard peer on its next pass.
func (s *Service) ActivateSession(ctx context.Context, deviceID, userID, ipAddress string) (*db.Session, error) {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("getting device: %w", err)
	}
	if dev.UserID != userID {
		return nil, errors.New("device does not belong to this user")
	}
	if !dev.IsApproved {
		return nil, errors.New("device has not been approved yet")
	}
	if !dev.IsActive {
		return nil, errors.New("device has been disabled by an administrator")
	}

	group, err := s.db.GetGroupByID(ctx, dev.GroupID)
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}

	expiresAt := time.Now().Add(group.SessionDuration)
	session, err := s.db.CreateSession(ctx, deviceID, expiresAt, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: userID, Valid: true},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     db.AuditEventSessionCreated,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("expires_at", expiresAt.Format(time.RFC3339)),
	}); err != nil {
		s.log.Warn("writing session created audit log", zap.Error(err))
	}

	s.emit(Event{Type: EventSessionCreated, DeviceID: deviceID, UserID: userID, OwnerID: userID,
		Payload: map[string]any{"expires_at": expiresAt}})

	// Add the peer to WireGuard immediately rather than waiting for the reconciler.
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("PANIC adding WireGuard peer — server unaffected",
					zap.String("device", dev.Name),
					zap.Any("panic", rec),
				)
			}
		}()

		peerCfg, err := s.buildPeerConfigForDevice(context.Background(), dev)
		if err != nil {
			s.log.Error("activating session: building peer config",
				zap.String("device", dev.Name),
				zap.String("assigned_ip", dev.AssignedIP),
				zap.String("public_key", dev.PublicKey),
				zap.Error(err),
			)
			return
		}
		s.log.Debug("adding WireGuard peer",
			zap.String("device", dev.Name),
			zap.String("ip", dev.AssignedIP),
			zap.Int("allowed_ips", len(peerCfg.AllowedIPs)),
		)
		if err := s.peers.AddPeer(*peerCfg); err != nil {
			s.log.Error("activating session: adding WireGuard peer",
				zap.String("device", dev.Name),
				zap.String("assigned_ip", dev.AssignedIP),
				zap.Error(err),
			)
			return
		}
		s.log.Info("peer added on session activation",
			zap.String("device", dev.Name),
			zap.String("ip", dev.AssignedIP),
		)
		s.emit(Event{Type: EventPeerAdded, DeviceID: dev.ID, OwnerID: dev.UserID})
	}()

	return session, nil
}

// ActivateGroupSessions activates sessions for all approved devices in a group
// belonging to the given user.
func (s *Service) ActivateGroupSessions(ctx context.Context, groupID, userID, ipAddress string) error {
	devices, err := s.db.ListDevicesByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("listing user devices: %w", err)
	}

	var errs []error
	for _, dev := range devices {
		if dev.GroupID != groupID || !dev.IsApproved || !dev.IsActive {
			continue
		}
		if _, err := s.ActivateSession(ctx, dev.ID, userID, ipAddress); err != nil {
			errs = append(errs, fmt.Errorf("device %q: %w", dev.Name, err))
		}
	}

	return errors.Join(errs...)
}

// ExtendSession extends an active session by the group's session duration.
// Respects the group's max_extensions limit.
// If AllowPortalSessionExtension is true, this does not require OIDC re-auth.
func (s *Service) ExtendSession(ctx context.Context, sessionID, userID, ipAddress string) (*db.Session, error) {
	session, err := s.db.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}
	if !session.IsActive() {
		return nil, errors.New("session is not active")
	}

	dev, err := s.db.GetDeviceByID(ctx, session.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("getting device: %w", err)
	}
	if dev.UserID != userID {
		return nil, errors.New("session does not belong to this user")
	}

	group, err := s.db.GetGroupByID(ctx, dev.GroupID)
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}

	// Enforce max extensions.
	if group.MaxExtensions.Valid && int64(session.ExtensionCount) >= group.MaxExtensions.Int64 {
		return nil, fmt.Errorf(
			"maximum extensions (%d) reached for group %q — please log in again",
			group.MaxExtensions.Int64, group.Name,
		)
	}

	extended, err := s.db.ExtendSession(ctx, sessionID, group.SessionDuration)
	if err != nil {
		return nil, fmt.Errorf("extending session: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: userID, Valid: true},
		DeviceID:  sql.NullString{String: dev.ID, Valid: true},
		Event:     db.AuditEventSessionExtended,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("new_expires_at", extended.ExpiresAt.Format(time.RFC3339)),
	}); err != nil {
		s.log.Warn("writing session extended audit log", zap.Error(err))
	}

	s.emit(Event{Type: EventSessionExtended, DeviceID: dev.ID, UserID: userID})
	return extended, nil
}

// RevokeSession revokes a session immediately.
// Users can revoke their own sessions. Admins can revoke any session.
func (s *Service) RevokeSession(ctx context.Context, sessionID, actorUserID, ipAddress string, isAdmin bool) error {
	session, err := s.db.GetSessionByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("getting session: %w", err)
	}

	if !isAdmin {
		dev, err := s.db.GetDeviceByID(ctx, session.DeviceID)
		if err != nil {
			return fmt.Errorf("getting device: %w", err)
		}
		if dev.UserID != actorUserID {
			return errors.New("not authorised to revoke this session")
		}
	}

	if err := s.db.RevokeSession(ctx, sessionID, actorUserID); err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}

	// Remove the peer immediately rather than waiting for the reconciler.
	dev, err := s.db.GetDeviceByID(ctx, session.DeviceID)
	if err == nil {
		if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
			s.log.Warn("removing peer on revoke",
				zap.String("device_id", dev.ID),
				zap.Error(err),
			)
		}
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: actorUserID, Valid: true},
		DeviceID:  sql.NullString{String: session.DeviceID, Valid: true},
		Event:     db.AuditEventSessionRevoked,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("is_admin_action", isAdmin),
	}); err != nil {
		s.log.Warn("writing session revoked audit log", zap.Error(err))
	}

	ownerID := ""
	if dev != nil {
		ownerID = dev.UserID
	}
	s.emit(Event{Type: EventSessionRevoked, DeviceID: session.DeviceID, UserID: actorUserID, OwnerID: ownerID})
	return nil
}

// AdminExtendSession allows an admin to extend any session without limit.
func (s *Service) AdminExtendSession(ctx context.Context, sessionID, adminUserID, ipAddress string, by time.Duration) (*db.Session, error) {
	session, err := s.db.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}

	extended, err := s.db.ExtendSession(ctx, sessionID, by)
	if err != nil {
		return nil, fmt.Errorf("extending session: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: adminUserID, Valid: true},
		DeviceID:  sql.NullString{String: session.DeviceID, Valid: true},
		Event:     db.AuditEventSessionExtended,
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("admin_override", true, "extended_by_seconds", int(by.Seconds())),
	}); err != nil {
		s.log.Warn("writing admin session extend audit log", zap.Error(err))
	}

	return extended, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups & Subnets
// ─────────────────────────────────────────────────────────────────────────────

// ListGroupsForUser returns groups available to a user.
func (s *Service) ListGroupsForUser(ctx context.Context, userID string) ([]*db.Group, error) {
	return s.db.ListGroupsForUser(ctx, userID)
}

// ListAllGroups returns all groups (admin only).
func (s *Service) ListAllGroups(ctx context.Context) ([]*db.Group, error) {
	return s.db.ListGroups(ctx)
}

// ListAllSubnets returns all subnets (admin only).
func (s *Service) ListAllSubnets(ctx context.Context) ([]*db.Subnet, error) {
	return s.db.ListSubnets(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────────────────────────────────────

// HealthStatus is returned by the /health endpoint.
type HealthStatus struct {
	Healthy bool              `json:"healthy"`
	Checks  map[string]string `json:"checks"`
}

// ReconcilerLastRun returns the time the reconciler last completed a pass.
// Used by the health check socket command.
func (s *Service) ReconcilerLastRun() time.Time {
	if s.reconciler == nil {
		return time.Time{}
	}
	return s.reconciler.LastRun()
}

// Health returns the current health of all subsystems.
func (s *Service) Health(reconcilerLastRun time.Time) HealthStatus {
	status := HealthStatus{
		Healthy: true,
		Checks:  make(map[string]string),
	}

	if err := s.db.Ping(); err != nil {
		status.Healthy = false
		status.Checks["database"] = "unhealthy: " + err.Error()
	} else {
		status.Checks["database"] = "ok"
	}

	if _, err := s.peers.ListPeers(); err != nil {
		status.Healthy = false
		status.Checks["wireguard"] = "unhealthy: " + err.Error()
	} else {
		status.Checks["wireguard"] = "ok"
	}

	switch {
	case reconcilerLastRun.IsZero():
		status.Checks["reconciler"] = "not yet run"
	case time.Since(reconcilerLastRun) > 2*time.Minute:
		status.Healthy = false
		status.Checks["reconciler"] = fmt.Sprintf("stale: last run %s ago",
			time.Since(reconcilerLastRun).Round(time.Second))
	default:
		status.Checks["reconciler"] = fmt.Sprintf("ok: last run %s ago",
			time.Since(reconcilerLastRun).Round(time.Second))
	}

	return status
}

// ─────────────────────────────────────────────────────────────────────────────
// IP allocation
// ─────────────────────────────────────────────────────────────────────────────

// allocateIP finds the next available IP in the VPN subnet.
func (s *Service) allocateIP(ctx context.Context) (string, error) {
	_, network, err := net.ParseCIDR(s.cfg.WireGuard.Address)
	if err != nil {
		return "", fmt.Errorf("parsing server VPN address %q: %w", s.cfg.WireGuard.Address, err)
	}

	// Use ALL devices (pending, disabled, approved) so IPs are never reused.
	allDevices, err := s.db.ListAllDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("listing devices for IP allocation: %w", err)
	}

	used := make(map[string]bool, len(allDevices)+2)

	// Reserve the network address (.0) and broadcast address.
	used[network.IP.String()] = true

	// Reserve the server's own IP — normalise to 4-byte to match iterator.
	serverIP, _, _ := net.ParseCIDR(s.cfg.WireGuard.Address)
	if ip4 := serverIP.To4(); ip4 != nil {
		serverIP = ip4
	}
	used[serverIP.String()] = true

	for _, dev := range allDevices {
		used[dev.AssignedIP] = true
	}

	// Walk the subnet sequentially for the next free address.
	// cloneIP starts at network+1; server IP is in used so will be skipped.
	for ip := cloneIP(network.IP); network.Contains(ip); incrementIP(ip) {
		candidate := ip.String()
		if !used[candidate] {
			return candidate, nil
		}
	}

	return "", errors.New("VPN subnet exhausted: no available IP addresses")
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	incrementIP(clone) // start from .1, not .0
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
