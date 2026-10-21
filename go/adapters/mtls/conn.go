package mtls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
)

// ErrConnectionExpired is the error of a request on a connection whose status
// record is older than the status bound (MTLS-19). It wraps
// [adapter.ErrDependencyUnavailable], so the result is DEFERRED; the gateway
// then closes the connection after the response ([CloseAfter]), so that the
// client opens a new, fully authenticated one.
var ErrConnectionExpired = fmt.Errorf("mtls: the connection's status record is older than the status bound; open a new connection: %w", adapter.ErrDependencyUnavailable)

// connRecord is the state the adapter keeps for one connection: its status
// record (MTLS-19), created by the first successful evaluation and never
// refreshed.
type connRecord struct {
	mu sync.Mutex
	// set says that the record exists.
	set bool
	// observedAt is the instant of the first evaluation of the connection.
	observedAt time.Time
	// statusTime is u, the thisUpdate of the snapshot that evaluation used.
	statusTime time.Time
}

// connKey is the context key of a connection's record. It holds the adapter
// of the listener that accepted the connection, so a record of another
// listener is not this one's, and no request header can carry it.
type connKey struct{ a *Adapter }

// ConnContext is the http.Server ConnContext of the listener: it gives every
// connection the listener accepts its status record. A request whose context
// has no record of this adapter did not arrive through the listener, and
// AuthenticateNative refuses it.
func (a *Adapter) ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connKey{a}, &connRecord{})
}

// Arrive returns r as a request of a new connection accepted by the listener.
// A gateway sets ConnContext on its http.Server instead; Arrive is the same
// mark for a request that is handed to the adapter outside a server, as the
// conformance suite does.
func (a *Adapter) Arrive(r *http.Request) *http.Request {
	return r.WithContext(a.ConnContext(r.Context(), nil))
}

func (a *Adapter) record(r *http.Request) *connRecord {
	rec, _ := r.Context().Value(connKey{a}).(*connRecord)
	return rec
}

// CloseAfter marks the response so that the server closes the connection
// after it when err says that the client must open a new connection, or that
// native authentication failed on an open connection (MTLS-20, MTLS-21,
// MTLS-29). HTTP/1.1 sends Connection: close; the HTTP/2 server of net/http
// starts a graceful shutdown with GOAWAY instead. It reports whether it
// marked the response.
func CloseAfter(w http.ResponseWriter, err error) bool {
	var d *adapter.NativeDenial
	if errors.Is(err, ErrConnectionExpired) || (errors.As(err, &d) && d.PublicReason() == adapter.DenialCredentialRejected) {
		w.Header().Set("Connection", "close")
		return true
	}
	return false
}

// ServerTLSConfig returns the TLS configuration of the listener with the
// server certificates certs (MTLS-1, MTLS-17): TLS 1.3 only, a client
// certificate required, no session tickets and no session cache, and a
// connection refused at setup when its peer leaf fails MTLS-3 to MTLS-7, when
// the stack reports it as resumed, or, on a terminated listener, when the
// peer is not an allowlisted terminator (MTLS-23). The checks run again for
// every request (MTLS-18).
func (a *Adapter) ServerTLSConfig(certs []tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:           certs,
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.DidResume {
				return errors.New("mtls: resumed sessions are refused")
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("mtls: no client certificate")
			}
			v, err := a.verifyLeaf(cs.PeerCertificates[0], cs.PeerCertificates[1:], a.cfg.Clock.Now())
			if err != nil {
				return err
			}
			if a.cfg.Role == RoleTerminated && !a.terminator(v.workload) {
				return errors.New("mtls: the peer is not an allowlisted terminator")
			}
			return nil
		},
	}
}

func (a *Adapter) terminator(w adapter.Workload) bool {
	for _, t := range a.cfg.Terminators {
		if t == w {
			return true
		}
	}
	return false
}
