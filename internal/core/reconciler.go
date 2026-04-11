package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/wireguard"
)

// Reconciler periodically compares the database state against the live
// WireGuard interface and reconciles any differences. It:
//
//   - Marks expired sessions in the DB
//   - Removes peers whose sessions have expired or been revoked
//   - Re-adds peers whose sessions are active but missing from WireGuard
//     (e.g. after a container restart)
//   - Samples per-peer metrics into metric_snapshots
//   - Prunes old metric rows beyond the retention window
type Reconciler struct {
	db     *db.DB
	peers  wireguard.PeerManager
	svc    *Service
	log    *zap.Logger
	retain time.Duration // metric retention window

	mu      sync.Mutex
	lastRun time.Time
}

// NewReconciler creates a Reconciler.
func NewReconciler(database *db.DB, peers wireguard.PeerManager, svc *Service, retainMetrics time.Duration, log *zap.Logger) *Reconciler {
	return &Reconciler{
		db:     database,
		peers:  peers,
		svc:    svc,
		log:    log,
		retain: retainMetrics,
	}
}

// LastRun returns the time the most recent reconcile pass completed.
func (r *Reconciler) LastRun() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastRun
}

// Run starts the reconciliation loop, ticking at interval until ctx is cancelled.
// An initial pass runs immediately on startup to restore peer state after restarts.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) {
	r.log.Info("reconciler started", zap.Duration("interval", interval))

	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}

	r.pass()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.log.Info("reconciler stopped")
			return
		case <-ticker.C:
			r.pass()
		}
	}
}

// pass executes one full reconciliation cycle.
// Recovers from panics so a bug in peer management never crashes the server.
func (r *Reconciler) pass() {
	defer func() {
		if rec := recover(); rec != nil {
			r.log.Error("reconciler: panic recovered — server remains running",
				zap.Any("panic", rec),
			)
		}
	}()

	start := time.Now()
	ctx := context.Background()

	r.markExpiredSessions(ctx)
	r.removeExpiredPeers(ctx)
	r.ensureActivePeers(ctx)
	r.sampleMetrics(ctx)
	r.pruneMetrics(ctx)

	r.mu.Lock()
	r.lastRun = time.Now()
	r.mu.Unlock()

	r.log.Debug("reconciler pass complete", zap.Duration("duration", time.Since(start)))
}

// markExpiredSessions updates the DB status of sessions past their expiry time.
func (r *Reconciler) markExpiredSessions(ctx context.Context) {
	n, err := r.db.MarkExpiredSessions(ctx)
	if err != nil {
		r.log.Error("reconciler: marking expired sessions", zap.Error(err))
		return
	}
	if n > 0 {
		r.log.Info("reconciler: marked sessions as expired", zap.Int64("count", n))
	}
}

// removeExpiredPeers removes WireGuard peers whose sessions have expired or been revoked.
func (r *Reconciler) removeExpiredPeers(ctx context.Context) {
	// Find devices that are approved+active but have no valid active session —
	// these peers should not be in WireGuard.
	rows, err := r.db.SQL().QueryContext(ctx, `
		SELECT DISTINCT d.id, d.public_key, d.name, u.email
		FROM devices d
		JOIN users u ON u.id = d.user_id
		WHERE d.is_approved = 1
		  AND d.is_active   = 1
		  AND NOT EXISTS (
		      SELECT 1 FROM sessions s
		      WHERE s.device_id = d.id
		        AND s.status = 'active'
		        AND s.expires_at > ?
		  )
	`, time.Now().UTC())
	if err != nil {
		r.log.Error("reconciler: querying peers to remove", zap.Error(err))
		return
	}
	defer rows.Close()

	type peerRow struct {
		deviceID  string
		publicKey string
		name      string
		email     string
	}

	var toRemove []peerRow
	for rows.Next() {
		var p peerRow
		if err := rows.Scan(&p.deviceID, &p.publicKey, &p.name, &p.email); err != nil {
			r.log.Error("reconciler: scanning peer row", zap.Error(err))
			continue
		}
		toRemove = append(toRemove, p)
	}
	if err := rows.Err(); err != nil {
		r.log.Error("reconciler: iterating peer rows", zap.Error(err))
	}

	// Build set of keys currently in WireGuard so we only remove what's actually there.
	currentPeers, _ := r.peers.ListPeers()
	inWG := make(map[string]bool, len(currentPeers))
	for _, k := range currentPeers {
		inWG[k] = true
	}

	for _, p := range toRemove {
		if !inWG[p.publicKey] {
			// Not in WireGuard — nothing to remove.
			continue
		}
		if err := r.peers.RemovePeer(p.publicKey); err != nil {
			r.log.Error("reconciler: removing peer",
				zap.String("device", p.name),
				zap.String("user", p.email),
				zap.Error(err),
			)
			continue
		}

		r.log.Info("reconciler: removed peer (session expired/revoked)",
			zap.String("device", p.name),
			zap.String("user", p.email),
		)

		_ = r.db.WriteAuditLog(ctx, &db.AuditLog{
			DeviceID: sql.NullString{String: p.deviceID, Valid: true},
			Event:    db.AuditEventPeerRemoved,
			Metadata: db.AuditMeta("reason", "session_expired_or_revoked"),
		})

		r.svc.emit(Event{Type: EventPeerRemoved, DeviceID: p.deviceID})
	}
}

// ensureActivePeers adds any peers that have valid sessions but are missing
// from the WireGuard interface (e.g. after a restart).
func (r *Reconciler) ensureActivePeers(ctx context.Context) {
	// Get all currently configured peer public keys from WireGuard.
	presentKeys, err := r.peers.ListPeers()
	if err != nil {
		r.log.Error("reconciler: listing WireGuard peers", zap.Error(err))
		return
	}

	inWG := make(map[string]bool, len(presentKeys))
	for _, k := range presentKeys {
		inWG[k] = true
	}

	// Find devices with active sessions.
	rows, err := r.db.SQL().QueryContext(ctx, `
		SELECT d.id, d.public_key, d.assigned_ip, d.name, u.email
		FROM devices d
		JOIN users u ON u.id = d.user_id
		WHERE d.is_approved = 1
		  AND d.is_active   = 1
		  AND EXISTS (
		      SELECT 1 FROM sessions s
		      WHERE s.device_id = d.id
		        AND s.status = 'active'
		        AND s.expires_at > ?
		  )
	`, time.Now().UTC())
	if err != nil {
		r.log.Error("reconciler: querying active peers", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			deviceID, publicKey, assignedIP string
			name, email                     string
		)
		if err := rows.Scan(&deviceID, &publicKey, &assignedIP, &name, &email); err != nil {
			r.log.Error("reconciler: scanning active peer row", zap.Error(err))
			continue
		}

		// Already present — nothing to do.
		if inWG[publicKey] {
			continue
		}

		// Missing from WireGuard — rebuild peer config and re-add.
		peerCfg, err := r.buildPeerConfig(ctx, deviceID, publicKey, assignedIP)
		if err != nil {
			r.log.Error("reconciler: building peer config",
				zap.String("device", name),
				zap.Error(err),
			)
			continue
		}

		if err := r.peers.AddPeer(*peerCfg); err != nil {
			r.log.Error("reconciler: re-adding missing peer",
				zap.String("device", name),
				zap.String("user", email),
				zap.Error(err),
			)
			continue
		}

		r.log.Info("reconciler: restored missing peer",
			zap.String("device", name),
			zap.String("user", email),
		)

		_ = r.db.WriteAuditLog(ctx, &db.AuditLog{
			DeviceID: sql.NullString{String: deviceID, Valid: true},
			Event:    db.AuditEventPeerAdded,
			Metadata: db.AuditMeta("reason", "reconciler_restore"),
		})

		r.svc.emit(Event{Type: EventPeerAdded, DeviceID: deviceID})
	}

	if err := rows.Err(); err != nil {
		r.log.Error("reconciler: iterating active peers", zap.Error(err))
	}
}

// buildPeerConfig constructs a wireguard.PeerConfig for a device.
// Uses device-level subnet overrides if present, otherwise falls back to group subnets.
func (r *Reconciler) buildPeerConfig(ctx context.Context, deviceID, publicKey, assignedIP string) (*wireguard.PeerConfig, error) {
	subnets, err := r.db.ListSubnetsForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("listing subnets: %w", err)
	}

	allowedIPs := make([]net.IPNet, 0, len(subnets)+1)
	for _, s := range subnets {
		_, ipNet, err := net.ParseCIDR(s.CIDR)
		if err != nil {
			r.log.Warn("skipping invalid subnet CIDR", zap.String("cidr", s.CIDR), zap.Error(err))
			continue
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}

	// Fall back to VPN subnet so the peer can at least reach the server.
	if len(allowedIPs) == 0 {
		_, vpnNet, err := net.ParseCIDR(r.svc.cfg.WireGuard.Address)
		if err == nil {
			allowedIPs = append(allowedIPs, *vpnNet)
		}
	}

	ip := net.ParseIP(assignedIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid assigned IP %q", assignedIP)
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	return &wireguard.PeerConfig{
		PublicKey:  publicKey,
		AssignedIP: ip,
		AllowedIPs: allowedIPs,
	}, nil
}

// sampleMetrics reads stats from WireGuard and writes a snapshot per peer.
func (r *Reconciler) sampleMetrics(ctx context.Context) {
	stats, err := r.peers.GetStats()
	if err != nil {
		r.log.Error("reconciler: getting WireGuard stats", zap.Error(err))
		return
	}

	for _, stat := range stats {
		dev, err := r.db.GetDeviceByPublicKey(ctx, stat.PublicKey)
		if errors.Is(err, sql.ErrNoRows) {
			// Peer in WireGuard but not in our DB — manually added, skip.
			continue
		}
		if err != nil {
			r.log.Error("reconciler: looking up device by public key", zap.Error(err))
			continue
		}

		snap := &db.MetricSnapshot{
			DeviceID:      dev.ID,
			BytesSent:     stat.BytesSent,
			BytesReceived: stat.BytesReceived,
		}
		if !stat.LastHandshake.IsZero() {
			snap.LastHandshake = sql.NullTime{Time: stat.LastHandshake, Valid: true}
		}

		r.log.Debug("metric sample",
			zap.String("device", dev.Name),
			zap.Int64("bytes_sent", stat.BytesSent),
			zap.Int64("bytes_received", stat.BytesReceived),
			zap.Time("last_handshake", stat.LastHandshake),
		)

		if err := r.db.InsertMetricSnapshot(ctx, snap); err != nil {
			r.log.Error("reconciler: inserting metric snapshot", zap.Error(err))
		}
	}
}

// pruneMetrics deletes old metric snapshots beyond the retention window.
func (r *Reconciler) pruneMetrics(ctx context.Context) {
	cutoff := time.Now().Add(-r.retain)
	n, err := r.db.PruneOldMetrics(ctx, cutoff)
	if err != nil {
		r.log.Error("reconciler: pruning old metrics", zap.Error(err))
		return
	}
	if n > 0 {
		r.log.Debug("reconciler: pruned old metric snapshots", zap.Int64("count", n))
	}
}
