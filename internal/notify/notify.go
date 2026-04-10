// Package notify handles email notifications for wicket events.
// All methods are safe to call when SMTP is disabled — they no-op cleanly.
package notify

import (
	"context"
	"fmt"

	"github.com/wneessen/go-mail"
	"go.uber.org/zap"

	"github.com/wicket-vpn/wicket/internal/config"
)

// Notifier sends email notifications.
type Notifier struct {
	cfg *config.SMTPConfig
	log *zap.Logger
}

// New creates a Notifier. If SMTP is disabled, all methods are no-ops.
func New(cfg *config.SMTPConfig, log *zap.Logger) *Notifier {
	return &Notifier{cfg: cfg, log: log}
}

// DeviceApproved notifies a user that their device has been approved.
func (n *Notifier) DeviceApproved(ctx context.Context, toEmail, deviceName string) {
	if !n.cfg.Enabled {
		return
	}
	subject := fmt.Sprintf("Your device %q has been approved — Wicket", deviceName)
	body := fmt.Sprintf("Your WireGuard device %q has been approved and is now active.\n\nLog in to activate your session.\n\n— Wicket", deviceName)
	n.send(toEmail, subject, body)
}

// DeviceRejected notifies a user that their device was rejected.
func (n *Notifier) DeviceRejected(ctx context.Context, toEmail, deviceName string) {
	if !n.cfg.Enabled {
		return
	}
	subject := fmt.Sprintf("Your device request %q was not approved — Wicket", deviceName)
	body := fmt.Sprintf("Your request for device %q was not approved.\n\nContact your administrator if you think this is an error.\n\n— Wicket", deviceName)
	n.send(toEmail, subject, body)
}

// SessionExpiringSoon warns a user their session will expire soon.
func (n *Notifier) SessionExpiringSoon(ctx context.Context, toEmail, deviceName, expiresIn string) {
	if !n.cfg.Enabled {
		return
	}
	subject := fmt.Sprintf("VPN session expiring in %s — %s", expiresIn, deviceName)
	body := fmt.Sprintf("Your VPN session for %q expires in %s.\n\nLog in to extend it.\n\n— Wicket", deviceName, expiresIn)
	n.send(toEmail, subject, body)
}

// send dispatches an email in a goroutine. Errors are logged, never propagated.
func (n *Notifier) send(to, subject, body string) {
	go func() {
		if err := n.sendSync(to, subject, body); err != nil {
			n.log.Warn("sending notification email",
				zap.String("to", to),
				zap.String("subject", subject),
				zap.Error(err),
			)
		}
	}()
}

func (n *Notifier) sendSync(to, subject, body string) error {
	msg := mail.NewMsg()
	if err := msg.From(n.cfg.From); err != nil {
		return fmt.Errorf("setting from: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("setting to: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	opts := []mail.Option{
		mail.WithPort(n.cfg.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(n.cfg.Username),
		mail.WithPassword(n.cfg.Password),
	}
	if n.cfg.UseTLS {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(n.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("creating mail client: %w", err)
	}

	if err := client.DialAndSendWithContext(context.Background(), msg); err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	return nil
}
