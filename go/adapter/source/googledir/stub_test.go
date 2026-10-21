package googledir_test

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

type staticTokens string

func (s staticTokens) Token(ctx context.Context) (string, error) { return string(s), nil }

// stub is a TLS server with a handler the test writes, and a Client that
// reaches it for both APIs.
type stub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

func newStub(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *stub {
	s := &stub{}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Clone(r.Context()))
		s.mu.Unlock()
		h(w, r)
	}))
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func (s *stub) client(t *testing.T, clk clock.Clock) *googledir.Client {
	t.Helper()
	c, err := googledir.NewClient(googledir.ClientConfig{
		DirectoryURL: s.srv.URL + "/directory", IdentityURL: s.srv.URL + "/identity",
		ChannelsStopURL: s.srv.URL + "/channels/stop", HTTP: s.srv.Client(),
		DirectoryTokens: staticTokens("dir-tok"), IdentityTokens: staticTokens("ci-tok"), Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func at(sec int64) time.Time { return time.Unix(sec, 0) }
