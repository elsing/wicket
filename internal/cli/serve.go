package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/admin"
	"github.com/wicket-vpn/wicket/internal/config"
	"github.com/wicket-vpn/wicket/internal/core"
	"github.com/wicket-vpn/wicket/internal/notify"
	"github.com/wicket-vpn/wicket/internal/oidc"
	"github.com/wicket-vpn/wicket/internal/portal"
	"github.com/wicket-vpn/wicket/internal/ws"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Wicket server",
	Long: `Starts all subsystems:
  • Core server   (database, WireGuard, reconciler loop)
  • Public portal  on the configured bind address (default :8080)
  • Admin portal   on the configured bind address (default 127.0.0.1:9090)
  • Unix socket    for CLI admin commands`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	log, err := buildLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("initialising logger: %w", err)
	}
	defer log.Sync() //nolint:errcheck

	log.Info("wicket starting",
		zap.String("public_addr", cfg.Public.BindAddr),
		zap.String("admin_addr", cfg.Admin.BindAddr),
		zap.String("socket", cfg.Server.SocketPath),
		zap.String("wg_iface", cfg.WireGuard.Interface),
	)

	// ── Core server ───────────────────────────────────────────────────────────
	srv, err := core.New(cfg, log)
	if err != nil {
		return fmt.Errorf("initialising core: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── OIDC provider ─────────────────────────────────────────────────────────
	// Public portal OIDC — callback goes to external URL
	publicRedirectURL := cfg.Server.ExternalURL + "/auth/callback"
	publicOIDC, err := oidc.New(ctx, &cfg.OIDC, publicRedirectURL)
	if err != nil {
		return fmt.Errorf("initialising OIDC for public portal: %w", err)
	}

	// Admin portal OIDC — callback goes to admin external URL
	// Add admin.external_url to config, fall back to admin bind addr for local use
	adminRedirectURL := cfg.Admin.ExternalURL + "/auth/callback"
	if cfg.Admin.ExternalURL == "" {
		adminRedirectURL = "http://" + cfg.Admin.BindAddr + "/auth/callback"
	}
	adminOIDC, err := oidc.New(ctx, &cfg.OIDC, adminRedirectURL)
	if err != nil {
		return fmt.Errorf("initialising OIDC for admin portal: %w", err)
	}
	log.Info("OIDC providers ready",
		zap.String("issuer", cfg.OIDC.Issuer),
		zap.String("public_callback", publicRedirectURL),
		zap.String("admin_callback", adminRedirectURL),
	)

	// ── WebSocket hub ─────────────────────────────────────────────────────────
	hub := ws.New(srv.Service().Events(), log)
	go hub.Run(ctx)

	// ── Email notifier ────────────────────────────────────────────────────────
	notifier := notify.New(&cfg.SMTP, log)
	_ = notifier // wired into service handlers as needed

	// ── Portal handlers ───────────────────────────────────────────────────────
	publicHandler := portal.NewHandler(srv.Service(), publicOIDC, hub, cfg, log)
	adminHandler := admin.NewHandler(srv.Service(), adminOIDC, hub, srv.AgentHub(), cfg, log)

	srv.SetPublicHandler(publicHandler)
	srv.SetAdminHandler(adminHandler)

	// ── Start ─────────────────────────────────────────────────────────────────
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errCh <- err
		}
	}()

	log.Info("wicket ready ✓",
		zap.String("public_url", cfg.Server.ExternalURL),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("received signal", zap.String("signal", sig.String()))
	case err := <-errCh:
		log.Error("fatal server error", zap.Error(err))
		return err
	}

	cancel()
	return srv.Shutdown()
}

func buildLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var zapCfg zap.Config
	if cfg.Format == "console" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}

	level, err := zap.ParseAtomicLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("parsing log level %q: %w", cfg.Level, err)
	}
	zapCfg.Level = level
	return zapCfg.Build()
}
