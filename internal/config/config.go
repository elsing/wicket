// Package config defines all configuration types for wicket and handles
// loading from a YAML file with environment variable overrides for secrets.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	DB        DBConfig        `yaml:"db"`
	WireGuard WireGuardConfig `yaml:"wireguard"`
	OIDC      OIDCConfig      `yaml:"oidc"`
	Public    PublicConfig    `yaml:"public"`
	Admin     AdminConfig     `yaml:"admin"`
	SMTP      SMTPConfig      `yaml:"smtp"`
	Security  SecurityConfig  `yaml:"security"`
	Agent     AgentConfig     `yaml:"agent"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// ServerConfig holds general server settings.
type ServerConfig struct {
	// SocketPath is the Unix socket the CLI connects to.
	SocketPath string `yaml:"socket_path"`
	// ExternalURL is the public URL of the portal, used for OIDC redirect URIs
	// and config download links. Must not have a trailing slash.
	ExternalURL string `yaml:"external_url"`
	// Environment is "production" or "development". Controls cookie Secure flag.
	Environment string `yaml:"environment"`
}

// DBConfig holds database settings.
type DBConfig struct {
	// DSN format Postgres connection string.
	DSN string `yaml:"dsn"`
}

// WireGuardConfig holds WireGuard interface settings for the local peer manager.
type WireGuardConfig struct {
	// Interface is the WireGuard interface name, e.g. "wg0".
	Interface string `yaml:"interface"`
	// ListenPort is the UDP port WireGuard listens on.
	ListenPort int `yaml:"listen_port"`
	// PrivateKey is the server's WireGuard private key (base64).
	// Set via WICKET_WG_PRIVATE_KEY environment variable.
	PrivateKey string `yaml:"private_key"`
	// Address is the server's VPN interface address with CIDR, e.g. "10.10.0.1/24".
	Address string `yaml:"address"`
	// Endpoint is the public host:port announced to clients in generated WireGuard configs.
	// Must include the port, e.g. "vpn.example.com:51820" or "1.2.3.4:51820".
	// Do NOT include a scheme or trailing slash.
	Endpoint string `yaml:"endpoint"`
	// DNS servers pushed to clients in generated configs.
	DNS []string `yaml:"dns"`
	// MTU for the WireGuard interface. 0 = use default (1420).
	MTU int `yaml:"mtu"`
}

// OIDCConfig holds OpenID Connect settings for Authentik (or any OIDC provider).
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL, e.g.:
	// "https://authentik.example.com/application/o/wicket/"
	Issuer string `yaml:"issuer"`
	// ClientID — set via WICKET_OIDC_CLIENT_ID.
	ClientID string `yaml:"client_id"`
	// ClientSecret — set via WICKET_OIDC_CLIENT_SECRET.
	ClientSecret string `yaml:"client_secret"`
	// Scopes to request. openid, profile, and email are required.
	Scopes []string `yaml:"scopes"`
}

// PublicConfig holds public portal settings.
type PublicConfig struct {
	// BindAddr is the address the public portal listens on.
	BindAddr string `yaml:"bind_addr"`
	// SessionSecret signs portal session cookies.
	// Set via WICKET_PUBLIC_SESSION_SECRET. Min 32 bytes.
	SessionSecret string `yaml:"session_secret"`
	// SessionDuration is how long a portal login session lasts before requiring
	// full OIDC re-auth. VPN sessions are governed by the group's session_duration.
	SessionDuration time.Duration `yaml:"session_duration"`
}

// AdminConfig holds admin portal settings.
type AdminConfig struct {
	// BindAddr must be a private address — never 0.0.0.0.
	BindAddr string `yaml:"bind_addr"`
	// ExternalURL is the publicly reachable URL of the admin portal.
	// Required for the admin portal OIDC callback. Must be registered in Authentik.
	// e.g. https://wicket-admin.example.com
	ExternalURL string `yaml:"external_url"`
	// HMACSecret signs requests from admin portal to core.
	// Set via WICKET_ADMIN_HMAC_SECRET. Min 32 bytes.
	HMACSecret string `yaml:"hmac_secret"`
	// SessionSecret signs admin portal session cookies.
	// Set via WICKET_ADMIN_SESSION_SECRET. Min 32 bytes.
	SessionSecret string `yaml:"session_secret"`
}

// SMTPConfig holds email notification settings.
type SMTPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	// Password — set via WICKET_SMTP_PASSWORD.
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	// UseTLS: true = implicit TLS (port 465), false = STARTTLS (port 587).
	UseTLS bool `yaml:"use_tls"`
}

// SecurityConfig holds security policy settings.
type SecurityConfig struct {
	// RateLimitRequests is the max requests per RateLimitWindow on the public portal.
	RateLimitRequests int           `yaml:"rate_limit_requests"`
	RateLimitWindow   time.Duration `yaml:"rate_limit_window"`

	// AllowPortalSessionExtension allows VPN session extension without full OIDC
	// re-auth when the user's portal session is still valid.
	AllowPortalSessionExtension bool `yaml:"allow_portal_session_extension"`

	// MaxLoginAttempts before temporarily blocking an IP.
	MaxLoginAttempts   int           `yaml:"max_login_attempts"`
	LoginBlockDuration time.Duration `yaml:"login_block_duration"`
}

// AgentConfig holds settings for remote WireGuard agents.
type AgentConfig struct {
	// CoreURL is the WebSocket URL of the core, e.g. "ws://core.internal:8081/ws/agent"
	CoreURL string `yaml:"core_url"`
	// Token authenticates this agent to the core.
	// Set via WICKET_AGENT_TOKEN.
	Token string `yaml:"token"`
	// CoreTimeout: if core is unreachable for this long, purge all peers.
	// Acts as a dead man's switch — default 6h.
	CoreTimeout time.Duration `yaml:"core_timeout"`
	// WireGuard holds the agent's interface settings (overrides root wireguard config).
	WireGuard WireGuardConfig `yaml:"wireguard"`
}

// MetricsConfig controls metrics collection.
type MetricsConfig struct {
	// SampleInterval is how often the reconciler samples WireGuard stats.
	SampleInterval time.Duration `yaml:"sample_interval"`
	// RetentionDays is how long metric snapshots are kept.
	RetentionDays int `yaml:"retention_days"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	// Level: "debug", "info", "warn", "error".
	Level string `yaml:"level"`
	// Format: "json" (production) or "console" (development).
	Format string `yaml:"format"`
}

// Load reads and parses the config file at path, then applies environment
// variable overrides for all secrets. Returns a validated Config or an error.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file %q: %w", path, err)
	}
	defer f.Close()

	cfg := defaults()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // reject unknown keys — catches typos early
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required fields are present and logically valid.
// Called at startup so misconfiguration fails fast with a clear message.
func (c *Config) Validate() error {
	var errs []error

	require := func(val, name string) {
		if strings.TrimSpace(val) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}

	minLen := func(val, name string, min int) {
		if len(val) > 0 && len(val) < min {
			errs = append(errs, fmt.Errorf("%s must be at least %d characters", name, min))
		}
	}

	require(c.Server.ExternalURL, "server.external_url")
	require(c.WireGuard.PrivateKey, "wireguard.private_key (or WICKET_WG_PRIVATE_KEY)")
	require(c.WireGuard.Address, "wireguard.address")
	require(c.WireGuard.Endpoint, "wireguard.endpoint")
	require(c.OIDC.Issuer, "oidc.issuer")
	require(c.OIDC.ClientID, "oidc.client_id (or WICKET_OIDC_CLIENT_ID)")
	require(c.OIDC.ClientSecret, "oidc.client_secret (or WICKET_OIDC_CLIENT_SECRET)")
	require(c.Public.SessionSecret, "public.session_secret (or WICKET_PUBLIC_SESSION_SECRET)")
	require(c.Admin.HMACSecret, "admin.hmac_secret (or WICKET_ADMIN_HMAC_SECRET)")
	require(c.Admin.SessionSecret, "admin.session_secret (or WICKET_ADMIN_SESSION_SECRET)")

	minLen(c.Public.SessionSecret, "public.session_secret", 32)
	minLen(c.Admin.HMACSecret, "admin.hmac_secret", 32)
	minLen(c.Admin.SessionSecret, "admin.session_secret", 32)

	// Critical: admin portal must never be publicly exposed.
	if strings.HasPrefix(c.Admin.BindAddr, "0.0.0.0") {
		errs = append(errs, errors.New(
			"admin.bind_addr must not bind to 0.0.0.0 — the admin portal must never be publicly exposed",
		))
	}

	if c.Security.MaxLoginAttempts < 1 {
		errs = append(errs, errors.New("security.max_login_attempts must be at least 1"))
	}

	return errors.Join(errs...)
}

// applyEnvOverrides replaces config values with environment variable values
// when set. All secrets must be provided this way in production.
func applyEnvOverrides(cfg *Config) {
	env := func(target *string, key string) {
		if v := os.Getenv(key); v != "" {
			*target = v
		}
	}

	env(&cfg.WireGuard.PrivateKey, "WICKET_WG_PRIVATE_KEY")
	env(&cfg.OIDC.ClientID, "WICKET_OIDC_CLIENT_ID")
	env(&cfg.OIDC.ClientSecret, "WICKET_OIDC_CLIENT_SECRET")
	env(&cfg.Public.SessionSecret, "WICKET_PUBLIC_SESSION_SECRET")
	env(&cfg.Admin.HMACSecret, "WICKET_ADMIN_HMAC_SECRET")
	env(&cfg.Admin.SessionSecret, "WICKET_ADMIN_SESSION_SECRET")
	env(&cfg.SMTP.Password, "WICKET_SMTP_PASSWORD")
	env(&cfg.Agent.Token, "WICKET_AGENT_TOKEN")
}

// defaults returns a Config pre-filled with sensible defaults.
func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			SocketPath:  "/var/run/wicket/core.sock",
			Environment: "production",
		},
		DB: DBConfig{
			Path: "/data/wicket.db",
		},
		WireGuard: WireGuardConfig{
			Interface:  "wg1", // default to wg1 to avoid conflict with existing wg0
			ListenPort: 51820,
			DNS:        []string{"1.1.1.1", "1.0.0.1"},
			MTU:        1420,
		},
		OIDC: OIDCConfig{
			Scopes: []string{"openid", "profile", "email"},
		},
		Public: PublicConfig{
			BindAddr:        "0.0.0.0:8080",
			SessionDuration: 12 * time.Hour,
		},
		Admin: AdminConfig{
			BindAddr: "127.0.0.1:9090",
		},
		SMTP: SMTPConfig{
			Port: 587,
		},
		Security: SecurityConfig{
			RateLimitRequests:           60,
			RateLimitWindow:             time.Minute,
			AllowPortalSessionExtension: true,
			MaxLoginAttempts:            10,
			LoginBlockDuration:          15 * time.Minute,
		},
		Agent: AgentConfig{
			CoreTimeout: 6 * time.Hour,
		},
		Metrics: MetricsConfig{
			SampleInterval: 30 * time.Second,
			RetentionDays:  90,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}
