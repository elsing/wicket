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
	"strings"
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

// notifyAgentPeerRemove pushes a peer.remove to any agents managing the device's group.
// Called immediately on session revoke, device disable, or device delete.
func (s *Service) notifyAgentPeerRemove(ctx context.Context, dev *db.Device) {
	if s.reconciler == nil || s.reconciler.agentHub == nil {
		return
	}
	agentIDs := s.reconciler.getGroupAgentIDs(ctx, dev.GroupID)
	if len(agentIDs) == 0 {
		return
	}
	s.reconciler.agentHub.SendPeerRemove(agentIDs, dev.PublicKey, dev.ID)
}

// notifyAgentPeerUpdate sends a peer.add with updated ExpiresAt to agents.
// Called on session extension so the agent resets its expiry timer.
func (s *Service) notifyAgentPeerUpdate(ctx context.Context, dev *db.Device, session *db.Session) {
	if s.reconciler == nil || s.reconciler.agentHub == nil {
		return
	}
	agentIDs := s.reconciler.getGroupAgentIDs(ctx, dev.GroupID)
	if len(agentIDs) == 0 {
		return
	}
	routes, _ := s.db.ListRoutesForDevice(ctx, dev.ID)
	allowedIPs := []string{dev.AssignedIP + "/32"}
	for _, r := range routes {
		allowedIPs = append(allowedIPs, r.CIDR)
	}
	s.reconciler.agentHub.SendPeerAdd(agentIDs, AgentPeer{
		PublicKey:  dev.PublicKey,
		AssignedIP: dev.AssignedIP + "/32",
		AllowedIPs: allowedIPs,
		DeviceID:   dev.ID,
		DeviceName: dev.Name,
		ExpiresAt:  session.ExpiresAt,
	})
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
		if (!dev.AutoRenew && !dev.AlwaysConnected) || !dev.IsApproved || !dev.IsActive {
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
	assignedIP, err := s.allocateIP(ctx, groupID)
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

// excludeCIDR returns a list of CIDRs that cover all of 0.0.0.0/0
// EXCEPT the given cidr. This allows WireGuard AllowedIPs to route
// everything through the tunnel while bypassing a specific range.
// e.g. excludeCIDR("10.0.0.0/8") → all IPv4 except 10.0.0.0/8
func excludeCIDR(cidr string) []string {
	_, excl, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{"0.0.0.0/0"}
	}

	// Start with the full IPv4 space, then subtract the excluded block
	result := subtractCIDR("0.0.0.0/0", excl)
	return result
}

// subtractCIDR returns the CIDRs of (base minus excl) using binary splitting.
func subtractCIDR(baseStr string, excl *net.IPNet) []string {
	_, base, err := net.ParseCIDR(baseStr)
	if err != nil {
		return nil
	}
	return subtractNet(base, excl)
}

func subtractNet(base, excl *net.IPNet) []string {
	// If base and excl don't overlap, keep base as-is
	baseIP := base.IP.To4()
	exclIP := excl.IP.To4()
	if baseIP == nil || exclIP == nil {
		return []string{base.String()}
	}

	// Check overlap
	if !base.Contains(excl.IP) && !excl.Contains(base.IP) {
		return []string{base.String()}
	}

	// If excl contains base entirely, nothing remains
	if excl.Contains(base.IP) {
		baseLast := lastIP(base)
		if excl.Contains(baseLast) {
			return nil
		}
	}

	// If base == excl, nothing remains
	baseOnes, baseBits := base.Mask.Size()
	exclOnes, _ := excl.Mask.Size()
	if baseOnes == exclOnes && base.IP.Equal(excl.IP) {
		return nil
	}

	// Split base in half and recurse
	nextOnes := baseOnes + 1
	if nextOnes > baseBits {
		return []string{base.String()}
	}
	half1Str := fmt.Sprintf("%s/%d", baseIP.String(), nextOnes)
	_, h1, _ := net.ParseCIDR(half1Str)
	if h1 == nil {
		return []string{base.String()}
	}

	// Compute second half
	h2IP := make(net.IP, 4)
	copy(h2IP, h1.IP)
	h2IP = incrementIPBy(h2IP, 1<<uint(baseBits-nextOnes))
	h2Str := fmt.Sprintf("%s/%d", h2IP.String(), nextOnes)
	_, h2, _ := net.ParseCIDR(h2Str)
	if h2 == nil {
		return []string{base.String()}
	}

	var result []string
	result = append(result, subtractNet(h1, excl)...)
	result = append(result, subtractNet(h2, excl)...)
	return result
}

func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return n.IP
	}
	l := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		l[i] = ip[i] | ^n.Mask[i]
	}
	return l
}

func incrementIPBy(ip net.IP, n uint32) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return ip
	}
	v := (uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])) + n
	return net.IP{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// buildClientConfig assembles the WireGuard .conf for a device.
func (s *Service) buildClientConfig(ctx context.Context, dev *db.Device, privateKey string) (string, error) {
	subnets, err := s.db.ListRoutesForDevice(ctx, dev.ID)
	if err != nil {
		return "", fmt.Errorf("listing subnets for device: %w", err)
	}

	allowedIPs := make([]string, 0, len(subnets)+1)
	for _, sub := range subnets {
		if sub.IsExcluded {
			// Excluded routes: include 0.0.0.0/0 as the base, then route out
			// the excluded CIDR via the default gateway (not the tunnel).
			// WireGuard doesn't support exclusions natively — we approximate
			// by splitting the address space around the excluded block.
			for _, split := range excludeCIDR(sub.CIDR) {
				allowedIPs = append(allowedIPs, split)
			}
		} else {
			allowedIPs = append(allowedIPs, sub.CIDR)
		}
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

	// Determine server public key and endpoint from group/agent config.
	// Priority: group endpoint override > agent endpoint > global config.
	globalPubKey, err := wireguard.ServerPublicKey(s.cfg.WireGuard.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("deriving server public key: %w", err)
	}
	serverPubKey := globalPubKey
	endpoint := s.cfg.WireGuard.Endpoint

	if group, err := s.db.GetGroupByID(ctx, dev.GroupID); err == nil {
		if group.EndpointOverride != "" {
			endpoint = group.EndpointOverride
		}
		if agents, err := s.db.GetGroupAgents(ctx, dev.GroupID); err == nil {
			for _, a := range agents {
				if !a.IsActive {
					continue
				}
				// Use agent's WireGuard public key if available.
				// This is set when the agent connects and sends its ready message.
				if a.WGPublicKey != "" {
					serverPubKey = a.WGPublicKey
				}
				if group.EndpointOverride == "" && a.Endpoint != "" {
					endpoint = a.Endpoint
				}
				break
			}
		}
	}

	// Use group DNS if set, otherwise fall back to global config.
	dnsServers := s.cfg.WireGuard.DNS
	if group, err := s.db.GetGroupByID(ctx, dev.GroupID); err == nil && group.DNS != "" {
		// DNS stored as comma-separated string e.g. "1.1.1.1, 8.8.8.8"
		dnsServers = strings.Split(strings.ReplaceAll(group.DNS, " ", ""), ",")
	}

	conf := wireguard.BuildClientConfig(wireguard.ClientConfigParams{
		PrivateKey:      privateKey,
		AssignedIP:      dev.AssignedIP,
		DNS:             dnsServers,
		ServerPublicKey: serverPubKey,
		ServerEndpoint:  endpoint,
		AllowedIPs:      allowedIPs,
		MTU:             s.cfg.WireGuard.MTU,
	})

	return conf, nil
}

// buildPeerConfigForDevice constructs a wireguard.PeerConfig from a Device.
// Used for immediate peer addition on session activation.
func (s *Service) buildPeerConfigForDevice(ctx context.Context, dev *db.Device) (*wireguard.PeerConfig, error) {
	subnets, err := s.db.ListRoutesForDevice(ctx, dev.ID)
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

	s.WriteAdminAuditLog(ctx, adminUserID, db.AuditEventDeviceApproved, ipAddress, db.AuditMeta("device_name", dev.Name))

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
func (s *Service) DisableDevice(ctx context.Context, deviceID, actorUserID, ipAddress string) error {
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

	// Remove from local WireGuard unless agent-managed (agent handles its own WG).
	if !s.groupHasActiveAgent(ctx, dev.GroupID) {
		if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
			s.log.Warn("removing peer on disable", zap.String("device", dev.Name), zap.Error(err))
		}
	}
	s.notifyAgentPeerRemove(ctx, dev)
	if s.reconciler != nil {
		s.reconciler.Trigger()
	}

	// Mark disabled in DB
	if err := s.db.SetDeviceActive(ctx, deviceID, false); err != nil {
		return fmt.Errorf("disabling device: %w", err)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: actorUserID, Valid: actorUserID != ""},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     "device.disabled",
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("device_name", dev.Name),
	}); err != nil {
		s.log.Warn("writing device disabled audit log", zap.Error(err))
	}
	s.log.Info("device disabled", zap.String("device", dev.Name), zap.String("actor", actorUserID))
	s.emit(Event{Type: EventPeerRemoved, DeviceID: deviceID, UserID: actorUserID, OwnerID: dev.UserID})
	return nil
}

// DeleteDevice removes a device, revokes any active sessions, and removes the WireGuard peer.
func (s *Service) DeleteDevice(ctx context.Context, deviceID, actorUserID, ipAddress string, isAdmin bool) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}
	if !isAdmin && dev.UserID != actorUserID {
		return errors.New("not authorised to delete this device")
	}

	// Write audit log before deleting — device_id FK must still exist in the DB.
	// Even if the DB has ON DELETE SET NULL, writing before the delete is safer
	// and avoids FK violations on instances with the old NOT NULL constraint.
	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: actorUserID, Valid: actorUserID != ""},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     "device.deleted",
		IPAddress: ipAddress,
		Metadata:  db.AuditMeta("device_name", dev.Name),
	}); err != nil {
		s.log.Warn("writing device deleted audit log", zap.Error(err))
	}

	// Remove the WireGuard peer — skip local for agent-managed groups.
	if !s.groupHasActiveAgent(ctx, dev.GroupID) {
		if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
			s.log.Warn("removing peer on device delete", zap.String("device", dev.Name), zap.Error(err))
		}
	}
	s.notifyAgentPeerRemove(ctx, dev)

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

// RegenerateDevice generates a fresh WireGuard keypair for an existing device.
// The old peer is removed from WireGuard, the new public key is stored, and a
// new one-time config is returned. config_downloaded is reset so the user must
// re-download. The device keeps its assigned IP and group.
func (s *Service) RegenerateDevice(ctx context.Context, deviceID, userID string, isAdmin bool) (*CreateDeviceResult, error) {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("getting device: %w", err)
	}
	if !isAdmin && dev.UserID != userID {
		return nil, errors.New("not authorised to regenerate this device")
	}

	privateKey, publicKey, err := wireguard.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}

	// Remove old peer from WireGuard before updating the key.
	if !s.groupHasActiveAgent(ctx, dev.GroupID) {
		if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
			s.log.Warn("regenerate: removing old peer", zap.String("device", dev.Name), zap.Error(err))
		}
	}
	s.notifyAgentPeerRemove(ctx, dev)

	if err := s.db.UpdateDevicePublicKey(ctx, deviceID, publicKey); err != nil {
		return nil, fmt.Errorf("updating public key: %w", err)
	}

	// Reload device with new key.
	dev, err = s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("reloading device: %w", err)
	}

	// Revoke any active session — the peer needs re-adding after key change.
	if active, err := s.db.GetActiveSessionForDevice(ctx, deviceID); err == nil && active != nil {
		_ = s.RevokeSession(ctx, active.ID, userID, "system", isAdmin)
	}

	if err := s.db.WriteAuditLog(ctx, &db.AuditLog{
		UserID:    sql.NullString{String: userID, Valid: true},
		DeviceID:  sql.NullString{String: deviceID, Valid: true},
		Event:     "device.regenerated",
		IPAddress: "system",
		Metadata:  db.AuditMeta("device_name", dev.Name),
	}); err != nil {
		s.log.Warn("writing device regenerated audit log", zap.Error(err))
	}

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

// RenameDevice renames a device and emits a device.renamed event so all
// connected clients update in real-time without a full page refresh.
func (s *Service) RenameDevice(ctx context.Context, deviceID, name string) error {
	dev, err := s.db.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("getting device: %w", err)
	}
	if err := s.db.RenameDevice(ctx, deviceID, name); err != nil {
		return err
	}
	s.emit(Event{
		Type:    EventDeviceRenamed,
		DeviceID: deviceID,
		OwnerID: dev.UserID,
		Payload: map[string]any{"device_name": name},
	})
	return nil
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

// SetDeviceAlwaysConnected sets the always_connected flag on a device (admin only).
// Always-connected devices maintain an active session indefinitely and are never
// evicted by the reconciler — useful for servers and infrastructure devices.
// If enabling, any stale active sessions are cleared and a fresh one created.
func (s *Service) SetDeviceAlwaysConnected(ctx context.Context, deviceID string, enabled bool) error {
	if err := s.db.SetDeviceAlwaysConnected(ctx, deviceID, enabled); err != nil {
		return err
	}
	if enabled {
		dev, err := s.db.GetDeviceByID(ctx, deviceID)
		if err != nil {
			return err
		}
		if dev.IsApproved && dev.IsActive {
			// Clear any stale active sessions that could block the INSERT.
			if _, err := s.db.SQL().ExecContext(ctx,
				`UPDATE sessions SET status = 'expired' WHERE device_id = $1 AND status = 'active'`,
				deviceID); err != nil {
				s.log.Warn("always-connected: clearing stale session", zap.Error(err))
			}
			if _, err := s.ActivateSession(ctx, deviceID, dev.UserID, "system"); err != nil {
				s.log.Warn("always-connected: activating session on enable",
					zap.String("device", deviceID), zap.Error(err))
			}
		}
	}
	return nil
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

	// Idempotency guard — return existing active session if one already exists.
	// Prevents duplicate sessions from rapid double-clicks or concurrent requests.
	if existing, err := s.db.GetActiveSessionForDevice(ctx, deviceID); err == nil && existing != nil {
		return existing, nil
	}

	group, err := s.db.GetGroupByID(ctx, dev.GroupID)
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}

	var expiresAt time.Time
	if dev.AlwaysConnected || group.SessionDuration == 0 {
		expiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // effectively unlimited
	} else {
		expiresAt = time.Now().Add(group.SessionDuration)
	}
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
	if s.reconciler != nil {
		s.reconciler.Trigger()
	} // push peer to agents immediately

	// Add the peer to the local WireGuard interface, unless the group is managed
	// by a remote agent — in that case the agent handles its own WireGuard.
	if !s.groupHasActiveAgent(ctx, dev.GroupID) {
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
					zap.Error(err),
				)
				return
			}
			if err := s.peers.AddPeer(*peerCfg); err != nil {
				s.log.Error("activating session: adding WireGuard peer",
					zap.String("device", dev.Name),
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
	} else {
		s.log.Debug("skipping local WireGuard peer add — group is agent-managed",
			zap.String("device", dev.Name),
			zap.String("group", dev.GroupID),
		)
	}

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

	extendBy := group.SessionDuration
	if extendBy == 0 {
		extendBy = 100 * 365 * 24 * time.Hour
	}
	extended, err := s.db.ExtendSession(ctx, sessionID, extendBy)
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

	// Notify agents with the updated ExpiresAt so they reset their local expiry timers.
	s.notifyAgentPeerUpdate(ctx, dev, extended)

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

	// Remove the peer immediately.
	dev, err := s.db.GetDeviceByID(ctx, session.DeviceID)
	if err == nil {
		if s.groupHasActiveAgent(ctx, dev.GroupID) {
			// Agent-managed: notify agent directly for immediate removal.
			s.notifyAgentPeerRemove(ctx, dev)
		} else {
			if err := s.peers.RemovePeer(dev.PublicKey); err != nil {
				s.log.Warn("removing peer on revoke",
					zap.String("device_id", dev.ID),
					zap.Error(err),
				)
			}
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
	if s.reconciler != nil {
		s.reconciler.Trigger()
	} // remove peer from agents immediately
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

	// Notify agents so expiry timers are reset
	if dev, err := s.db.GetDeviceByID(ctx, extended.DeviceID); err == nil {
		s.notifyAgentPeerUpdate(ctx, dev, extended)
	}
	if s.reconciler != nil {
		s.reconciler.Trigger()
	}
	return extended, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Groups & Routes
// ─────────────────────────────────────────────────────────────────────────────

// ListGroupsForUser returns groups available to a user.
func (s *Service) ListGroupsForUser(ctx context.Context, userID string) ([]*db.Group, error) {
	return s.db.ListGroupsForUser(ctx, userID)
}

// ListAllGroups returns all groups (admin only).
func (s *Service) ListAllGroups(ctx context.Context) ([]*db.Group, error) {
	return s.db.ListGroups(ctx)
}

// ListAllRoutes returns all subnets (admin only).
func (s *Service) ListAllRoutes(ctx context.Context) ([]*db.Route, error) {
	return s.db.ListRoutes(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────────────────────────────────────

// HealthStatus is returned by the /health endpoint.
type HealthStatus struct {
	Healthy bool              `json:"healthy"`
	Checks  map[string]string `json:"checks"`
}

// Config returns the service configuration (read-only).
func (s *Service) Config() *config.Config {
	return s.cfg
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
// groupHasActiveAgent returns true if the group has at least one active agent assigned.
// For such groups, the agent manages WireGuard — the server should not touch its local
// WireGuard interface for devices in these groups.
func (s *Service) groupHasActiveAgent(ctx context.Context, groupID string) bool {
	agents, err := s.db.GetGroupAgents(ctx, groupID)
	if err != nil {
		return false
	}
	for _, a := range agents {
		if a.IsActive {
			return true
		}
	}
	return false
}

// IP allocation
// ─────────────────────────────────────────────────────────────────────────────

// allocateIP finds the next available IP for a device.
// If the group has an agent with a VPN pool, allocates from that pool.
// Otherwise falls back to the global VPN subnet from config.
func (s *Service) allocateIP(ctx context.Context, groupID string) (string, error) {
	// Try to get the pool from the group's assigned agent.
	poolCIDR := ""
	if groupID != "" {
		if agents, err := s.db.GetGroupAgents(ctx, groupID); err == nil && len(agents) > 0 {
			for _, a := range agents {
				if a.VPNPool != "" {
					poolCIDR = a.VPNPool
					break
				}
			}
		}
	}
	if poolCIDR == "" {
		poolCIDR = s.cfg.WireGuard.Address
	}

	_, network, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", fmt.Errorf("parsing VPN pool %q: %w", poolCIDR, err)
	}

	allDevices, err := s.db.ListAllDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("listing devices for IP allocation: %w", err)
	}

	used := make(map[string]bool, len(allDevices)+4)

	// Reserve network address (.0) and broadcast (last address).
	networkAddr := cloneIP4(network.IP)
	broadcast := broadcastIP(network)
	used[networkAddr.String()] = true
	used[broadcast.String()] = true

	// Reserve last usable IP — that's the agent/server interface address.
	lastUsable := lastUsableIP(network)
	used[lastUsable.String()] = true

	// Reserve the server's own configured IP if it falls in this pool.
	serverIP, _, _ := net.ParseCIDR(s.cfg.WireGuard.Address)
	if ip4 := serverIP.To4(); ip4 != nil && network.Contains(ip4) {
		used[ip4.String()] = true
	}

	for _, dev := range allDevices {
		used[dev.AssignedIP] = true
	}

	// Allocate bottom-up: start from .1, devices fill upward away from server.
	ip := cloneIP4(network.IP)
	incrementIP(ip) // skip network address
	for network.Contains(ip) {
		if !used[ip.String()] {
			return ip.String(), nil
		}
		incrementIP(ip)
	}

	return "", fmt.Errorf("VPN pool %s exhausted: no available IP addresses", poolCIDR)
}

// broadcastIP returns the broadcast address of a network.
func broadcastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return n.IP
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^n.Mask[i]
	}
	return bcast
}

// lastUsableIP returns the last usable IP in a network (broadcast - 1).
// This is reserved for the agent/server WireGuard interface.
func lastUsableIP(n *net.IPNet) net.IP {
	ip := broadcastIP(n)
	clone := cloneIP4(ip)
	decrementIP(clone)
	return clone
}

func cloneIP4(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = ip
	}
	clone := make(net.IP, len(ip4))
	copy(clone, ip4)
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

func decrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]--
		if ip[i] != 0xFF {
			break
		}
	}
}
