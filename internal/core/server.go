package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/config"
	"github.com/wicket-vpn/wicket/internal/db"
	"github.com/wicket-vpn/wicket/internal/wireguard"
)

// Server owns and coordinates all subsystems.
// Start() blocks until the context is cancelled; Shutdown() cleans up.
type Server struct {
	cfg        *config.Config
	log        *zap.Logger
	db         *db.DB
	peers      wireguard.PeerManager
	svc        *Service
	reconciler *Reconciler
	socket     *socketServer

	publicHTTP *http.Server
	adminHTTP  *http.Server
}

// New initialises the core server and all subsystems.
// Fails fast if the database or WireGuard interface are unavailable.
func New(cfg *config.Config, log *zap.Logger) (*Server, error) {
	// ── Database ─────────────────────────────────────────────────────────────
	database, err := db.Open(cfg.DB.Path)
	if err != nil {
		return nil, fmt.Errorf("opening database at %q: %w", cfg.DB.Path, err)
	}
	log.Info("database ready", zap.String("path", cfg.DB.Path))

	// ── WireGuard ─────────────────────────────────────────────────────────────
	pm, err := wireguard.NewLocalPeerManager(cfg.WireGuard.Interface)
	if err != nil {
		return nil, fmt.Errorf("initialising WireGuard peer manager: %w", err)
	}

	if err := pm.ConfigureServer(cfg.WireGuard.PrivateKey, cfg.WireGuard.ListenPort); err != nil {
		return nil, fmt.Errorf("configuring WireGuard server: %w", err)
	}
	log.Info("WireGuard ready",
		zap.String("interface", cfg.WireGuard.Interface),
		zap.Int("port", cfg.WireGuard.ListenPort),
	)

	// ── Service & Reconciler ─────────────────────────────────────────────────
	svc := NewService(database, pm, cfg, log)
	retainMetrics := time.Duration(cfg.Metrics.RetentionDays) * 24 * time.Hour
	rec := NewReconciler(database, pm, svc, retainMetrics, log)

	srv := &Server{
		cfg:        cfg,
		log:        log,
		db:         database,
		peers:      pm,
		svc:        svc,
		reconciler: rec,
	}

	srv.socket = newSocketServer(cfg.Server.SocketPath, svc, log)

	// HTTP servers are built with placeholder handlers; the serve command
	// injects real handlers via SetPublicHandler / SetAdminHandler before
	// calling Start().
	srv.publicHTTP = &http.Server{
		Addr:         cfg.Public.BindAddr,
		Handler:      http.NotFoundHandler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srv.adminHTTP = &http.Server{
		Addr:         cfg.Admin.BindAddr,
		Handler:      http.NotFoundHandler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return srv, nil
}

// SetPublicHandler replaces the public portal HTTP handler.
func (s *Server) SetPublicHandler(h http.Handler) { s.publicHTTP.Handler = h }

// SetAdminHandler replaces the admin portal HTTP handler.
func (s *Server) SetAdminHandler(h http.Handler) { s.adminHTTP.Handler = h }

// Service returns the core service for use by portal handlers.
func (s *Server) Service() *Service { return s.svc }

// Config returns the server configuration.
func (s *Server) Config() *config.Config { return s.cfg }

// Start launches all background goroutines and HTTP servers.
// Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	_ = os.Remove(s.cfg.Server.SocketPath)

	if dir := socketDir(s.cfg.Server.SocketPath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating socket directory %q: %w", dir, err)
		}
	}

	go s.reconciler.Run(ctx, s.cfg.Metrics.SampleInterval)

	go func() {
		if err := s.socket.Listen(ctx); err != nil {
			s.log.Error("socket server error", zap.Error(err))
		}
	}()
	s.log.Info("CLI socket listening", zap.String("path", s.cfg.Server.SocketPath))

	publicErrCh := make(chan error, 1)
	adminErrCh := make(chan error, 1)

	go func() {
		s.log.Info("public portal listening", zap.String("addr", s.cfg.Public.BindAddr))
		if err := s.publicHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("public portal died", zap.Error(err))
			publicErrCh <- err
		}
	}()

	go func() {
		s.log.Info("admin portal listening", zap.String("addr", s.cfg.Admin.BindAddr))
		if err := s.adminHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("admin portal died", zap.Error(err))
			adminErrCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-publicErrCh:
		return fmt.Errorf("public portal failed: %w", err)
	case err := <-adminErrCh:
		return fmt.Errorf("admin portal failed: %w", err)
	}
}

// Shutdown gracefully stops all subsystems.
func (s *Server) Shutdown() error {
	s.log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.publicHTTP.Shutdown(ctx); err != nil {
		s.log.Warn("public portal shutdown", zap.Error(err))
	}
	if err := s.adminHTTP.Shutdown(ctx); err != nil {
		s.log.Warn("admin portal shutdown", zap.Error(err))
	}
	s.socket.Close()
	_ = os.Remove(s.cfg.Server.SocketPath)

	if err := s.peers.Close(); err != nil {
		s.log.Warn("peer manager close", zap.Error(err))
	}
	if err := s.db.Close(); err != nil {
		s.log.Warn("database close", zap.Error(err))
	}

	s.log.Info("shutdown complete")
	return nil
}

// ReconcilerLastRun returns the last reconciler run time (for health checks).
func (s *Server) ReconcilerLastRun() time.Time { return s.reconciler.LastRun() }

func socketDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Unix socket server
// ─────────────────────────────────────────────────────────────────────────────

type socketServer struct {
	path     string
	svc      *Service
	log      *zap.Logger
	listener net.Listener
}

func newSocketServer(path string, svc *Service, log *zap.Logger) *socketServer {
	return &socketServer{path: path, svc: svc, log: log}
}

func (s *socketServer) Listen(ctx context.Context) error {
	l, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0600); err != nil {
		l.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}
	s.listener = l
	s.log.Info("Unix socket ready", zap.String("path", s.path))

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("socket accept: %w", err)
			}
		}
		go s.handleConn(conn)
	}
}

func (s *socketServer) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *socketServer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	dispatchSocketCommand(conn, s.svc, s.log)
}
