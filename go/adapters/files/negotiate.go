package files

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"hop.top/pact-go/adapter"
)

// connRecord is the Negotiate state of one connection (profile IA-10): the
// exchange in progress, or the completed context, and the WWW-Authenticate
// value of the last response.
type connRecord struct {
	mu        sync.Mutex
	partial   Exchange
	completed *completedContext
	challenge string
}

type completedContext struct {
	principal adapter.Principal
	ctx       Context
}

// connKey is the context key of a connection's record. It holds the broker
// that accepted the connection, so that no request header can carry it.
type connKey struct{ b *Broker }

// ConnContext is the http.Server ConnContext of the broker's listener: every
// connection the listener accepts gets its Negotiate state. A request whose
// context has no record of this broker did not arrive through the broker's
// listener, and AuthenticateNative refuses it.
func (b *Broker) ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connKey{b}, &connRecord{})
}

// Arrive returns r as a request of a new connection accepted by the broker's
// listener. A server sets ConnContext instead; Arrive is the same mark for a
// request handed to the broker outside a server, as the conformance suite
// does.
func (b *Broker) Arrive(r *http.Request) *http.Request {
	return r.WithContext(b.ConnContext(r.Context(), nil))
}

func (b *Broker) conn(r *http.Request) *connRecord {
	rec, _ := r.Context().Value(connKey{b}).(*connRecord)
	return rec
}

// Challenge returns the WWW-Authenticate value of the response to r: after a
// leg that needs another, Negotiate with the output token (RFC 4559, section
// 4.1, 5); after a completed exchange with a final token, that token; and
// otherwise Negotiate alone, which asks for a new exchange.
func (b *Broker) Challenge(r *http.Request) string {
	if rec := b.conn(r); rec != nil {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if rec.challenge != "" {
			return rec.challenge
		}
	}
	return "Negotiate"
}

func denial(reason adapter.DenialReason) error { return &adapter.NativeDenial{Reason: reason} }

// AuthenticateNative authenticates the request by the Negotiate exchange of
// its connection (profile 3.1). Identity headers are never read.
//
//   - A request that did not arrive through the broker's listener is
//     refused.
//   - A request with a Negotiate token runs the next leg of the
//     connection's exchange, or starts one. A leg that needs another is not
//     an authentication: NO_CREDENTIAL, with the output token in the
//     Challenge (IA-2). A failed leg deletes the partial context and the
//     connection's context, CREDENTIAL_REJECTED (IA-3). A completed
//     exchange whose token is below the impersonation level, or whose user
//     is not a SID, is CREDENTIAL_REJECTED (IA-6, IA-8).
//   - A request without one uses the connection's completed context while it
//     is not older than the context age, and is otherwise NO_CREDENTIAL with
//     a new challenge (IA-1, IA-9). Another authorization scheme is not a
//     credential of the broker.
//
// The principal and the workload are files:{domain-sid}:{user-sid}, and
// AuthenticatedAt is the instant the final leg returned.
func (b *Broker) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	rec := b.conn(r)
	if rec == nil {
		return adapter.Principal{}, fmt.Errorf("files: the request did not arrive through the broker's listener: %w", denial(adapter.DenialCredentialRejected))
	}
	if err := b.Healthy(); err != nil {
		return adapter.Principal{}, err
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	raw, present, err := negotiateToken(r.Header.Values("Authorization"))
	switch {
	case err != nil:
		rec.reset()
		return adapter.Principal{}, fmt.Errorf("files: %v: %w", err, denial(adapter.DenialCredentialRejected))
	case !present:
		return b.fromConnection(rec)
	}
	ex := rec.partial
	rec.partial = nil
	if ex == nil {
		if ex, err = b.cfg.Package.NewExchange(); err != nil {
			rec.reset()
			return adapter.Principal{}, fmt.Errorf("files: the security package cannot start an exchange: %v: %w", err, adapter.ErrDependencyUnavailable)
		}
	}
	out, tok, err := ex.Accept(raw)
	if err != nil {
		_ = ex.Close()
		rec.reset()
		return adapter.Principal{}, fmt.Errorf("files: the Negotiate exchange failed: %w", denial(adapter.DenialCredentialRejected))
	}
	if tok == nil {
		rec.partial = ex
		rec.completed = nil
		rec.challenge = "Negotiate " + base64.StdEncoding.EncodeToString(out)
		return adapter.Principal{}, fmt.Errorf("files: the Negotiate exchange needs another leg: %w", denial(adapter.DenialNoCredential))
	}
	_ = ex.Close()
	now := b.cfg.Clock.Now()
	id, err := PrincipalID(tok.User())
	if err != nil || tok.Level() < LevelImpersonation {
		_ = tok.Close()
		rec.reset()
		return adapter.Principal{}, fmt.Errorf("files: the completed context cannot be impersonated as a SID: %w", denial(adapter.DenialCredentialRejected))
	}
	p := adapter.Principal{ID: id, Realm: b.cfg.Realm, Workload: adapter.Workload(id), Mechanism: Mechanism, AuthenticatedAt: now}
	c := Context{Token: tok, CompletedAt: now}
	rec.completed = &completedContext{principal: p, ctx: c}
	rec.challenge = ""
	if len(out) > 0 {
		rec.challenge = "Negotiate " + base64.StdEncoding.EncodeToString(out)
	}
	b.contexts.Put(b.cfg.Realm, id, c)
	return p, nil
}

// fromConnection authenticates a request without a token by its connection's
// completed context.
func (b *Broker) fromConnection(rec *connRecord) (adapter.Principal, error) {
	c := rec.completed
	if c == nil || b.cfg.Clock.Now().Sub(c.ctx.CompletedAt) > b.cfg.ContextMaxAge {
		rec.reset()
		return adapter.Principal{}, fmt.Errorf("files: no current Negotiate context on the connection: %w", denial(adapter.DenialNoCredential))
	}
	rec.challenge = ""
	return c.principal, nil
}

// reset discards the connection's exchange and context, and asks for a new
// exchange.
func (rec *connRecord) reset() {
	if rec.partial != nil {
		_ = rec.partial.Close()
		rec.partial = nil
	}
	rec.completed = nil
	rec.challenge = "Negotiate"
}

// negotiateToken reads the one Authorization value with the Negotiate
// scheme (RFC 4559, section 4.2). No Negotiate value is not present; two
// Authorization values, or a token that is not base64, is an error.
func negotiateToken(values []string) ([]byte, bool, error) {
	var tokens []string
	for _, v := range values {
		if t, ok := strings.CutPrefix(v, "Negotiate "); ok {
			tokens = append(tokens, t)
		}
	}
	switch {
	case len(tokens) == 0:
		return nil, false, nil
	case len(values) != 1:
		return nil, true, fmt.Errorf("the request carries %d Authorization values", len(values))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tokens[0]))
	if err != nil || len(raw) == 0 {
		return nil, true, fmt.Errorf("the Negotiate token is not base64")
	}
	return raw, true, nil
}
