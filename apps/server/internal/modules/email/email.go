// Package email wraps SMTP send via wneessen/go-mail. SMTP settings live
// in the app_configs table, like the legacy backend.
package email

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"
	"github.com/wneessen/go-mail"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

type Service struct{ DB *sqlx.DB }

func (s *Service) Send(ctx context.Context, to, subject, htmlBody string) error {
	c := s.config(ctx)
	if !c.Enabled || c.Host == "" {
		return errors.New("SMTP disabled or not configured")
	}
	m := mail.NewMsg()
	if err := m.From(c.From); err != nil {
		return err
	}
	if err := m.To(to); err != nil {
		return err
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, htmlBody)

	opts := []mail.Option{
		mail.WithPort(c.Port),
		mail.WithUsername(c.User),
		mail.WithPassword(c.Pass),
	}
	if c.User == "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}
	if c.Secure {
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPortPolicy(mail.NoTLS))
	}
	cli, err := mail.NewClient(c.Host, opts...)
	if err != nil {
		return err
	}
	return cli.DialAndSendWithContext(ctx, m)
}

type smtpConfig struct {
	Enabled bool
	Host    string
	Port    int
	User    string
	Pass    string
	From    string
	Secure  bool
}

func (s *Service) config(ctx context.Context) smtpConfig {
	get := func(k string) string {
		var v string
		_ = s.DB.GetContext(ctx, &v, `SELECT value FROM app_configs WHERE key = ?`, k)
		return v
	}
	c := smtpConfig{
		Enabled: get("smtpEnabled") == "true",
		Host:    get("smtpHost"),
		User:    get("smtpUser"),
		Pass:    get("smtpPass"),
		From:    get("smtpFromEmail"),
		Secure:  get("smtpSecure") == "true",
	}
	if p, err := strconv.Atoi(get("smtpPort")); err == nil {
		c.Port = p
	}
	return c
}

// -----------------------------------------------------------------------------
// HTTP — /app/test-smtp
// -----------------------------------------------------------------------------

type Handler struct{ Svc *Service }

func Register(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/app/test-smtp",
		Tags: []string{"App"}, OperationID: "testSmtp",
	}, h.Test)
}

type EmailTestInput struct {
	Body struct {
		To string `json:"to" required:"true" format:"email"`
	}
}
// EmailTestOutput uses `success` (not `ok`) to match the frontend's
// `TestSmtpConnectionResult = { success, message }` shape — any caller
// branching on `response.data.success` would otherwise always see `undefined`.
type EmailTestOutput struct {
	Body struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

func (h *Handler) Test(ctx context.Context, in *EmailTestInput) (*EmailTestOutput, error) {
	// SECURITY: admin-only. The pre-fix endpoint only required
	// EnsureAuth, letting any logged-in user send a Palmr-signed mail
	// to any address (phishing-friendly, free-tier SMTP exhaustion).
	if _, err := auth.EnsureAdmin(ctx, h.Svc.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	err := h.Svc.Send(ctx, in.Body.To, "Palmr — SMTP test", "<p>If you see this, SMTP works.</p>")
	out := &EmailTestOutput{}
	if err != nil {
		out.Body.Success = false
		out.Body.Message = err.Error()
		return out, nil
	}
	out.Body.Success = true
	out.Body.Message = "sent"
	return out, nil
}
