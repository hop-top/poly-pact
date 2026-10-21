package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Server is the [Directory] of one LDAP server, on github.com/go-ldap/ldap/v3.
// It connects over LDAPS, or over LDAP followed by StartTLS, and never sends
// anything on an unprotected connection (profile LR-4).
type Server struct {
	// URL is ldaps://host[:port] or ldap://host[:port]; with ldap, StartTLS
	// must return success before anything else is sent.
	URL string
	// TLS holds the trust anchors (RootCAs) and the reference identity
	// (ServerName) of the server identity check (RFC 4513, section 3.1.3).
	// Required; InsecureSkipVerify is refused.
	TLS *tls.Config
	// Timeout bounds the dial and each request; zero is 10 seconds (LR-30).
	Timeout time.Duration
}

// Open dials the server and protects the connection.
func (s Server) Open(ctx context.Context) (Session, error) {
	if s.TLS == nil || s.TLS.InsecureSkipVerify {
		return nil, errors.New("ldap: the server needs a TLS configuration that verifies the server")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return nil, fmt.Errorf("ldap: server URL %q is not ldaps:// or ldap://", s.URL)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeLimit
	}
	cfg := s.TLS.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	d := &net.Dialer{Timeout: timeout}
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	conn, err := goldap.DialURL(s.URL, goldap.DialWithDialer(d), goldap.DialWithTLSConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	conn.SetTimeout(timeout)
	if u.Scheme == "ldap" {
		// A StartTLS that does not return success leaves the session
		// without TLS (RFC 4511, section 4.14.2), so it is closed.
		if err := conn.StartTLS(cfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap: StartTLS: %w", err)
		}
	}
	if _, ok := conn.TLSConnectionState(); !ok {
		_ = conn.Close()
		return nil, errors.New("ldap: the connection is not protected")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return &session{conn: conn, stop: stop}, nil
}

type session struct {
	conn *goldap.Conn
	stop func() bool
}

// resultError returns the result code of an LDAP result as a *ResultError,
// and any other error, such as a client-side or transport error, unchanged.
// go-ldap reports client-side conditions with codes from 200 up, outside the
// range of RFC 4511.
func resultError(err error) error {
	var le *goldap.Error
	if errors.As(err, &le) && le.ResultCode < 200 {
		return &ResultError{Code: ResultCode(le.ResultCode)}
	}
	return err
}

func (s *session) Bind(_ context.Context, dn, password string) error {
	if password == "" {
		return errors.New("ldap: refusing an unauthenticated bind")
	}
	// Conn.Bind refuses an empty password itself, before sending; the check
	// above does not rely on it.
	return resultError(s.conn.Bind(dn, password))
}

func (s *session) Search(_ context.Context, q Query) (Result, error) {
	scope := goldap.ScopeBaseObject
	if q.Scope == ScopeSubtree {
		scope = goldap.ScopeWholeSubtree
	}
	req := goldap.NewSearchRequest(q.Base, scope, goldap.NeverDerefAliases, q.SizeLimit,
		int((q.TimeLimit+time.Second-1)/time.Second), false, q.Filter.String(), q.Attributes, nil)
	res, err := s.conn.Search(req)
	out := Result{}
	if res != nil {
		for _, e := range res.Entries {
			ent := Entry{DN: e.DN}
			for _, a := range e.Attributes {
				ent.Attributes = append(ent.Attributes, Attribute{Name: a.Name, Values: a.ByteValues})
			}
			out.Entries = append(out.Entries, ent)
		}
		out.References = append(out.References, res.Referrals...)
	}
	if err != nil {
		var re *ResultError
		if errors.As(resultError(err), &re) {
			out.Code = re.Code
			return out, nil
		}
		return Result{}, err
	}
	return out, nil
}

func (s *session) WhoAmI(_ context.Context) (string, bool, error) {
	resp, err := s.conn.Extended(goldap.NewExtendedRequest(WhoAmIOID, nil))
	if err != nil {
		return "", false, resultError(err)
	}
	if resp.Value == nil {
		return "", false, nil
	}
	if resp.Value.Data == nil {
		return "", true, nil
	}
	return resp.Value.Data.String(), true, nil
}

func (s *session) Close() error {
	s.stop()
	err := s.conn.Close()
	if err != nil && strings.Contains(err.Error(), "closed") {
		return nil
	}
	return err
}
