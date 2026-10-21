package ssf_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
)

// gatedJWKS is a JWKS endpoint whose answers wait, while a gate is set, until
// the gate is opened.
type gatedJWKS struct {
	*httptest.Server
	hits    atomic.Int32
	body    atomic.Value // string
	gate    atomic.Pointer[chan struct{}]
	arrived chan struct{}
}

func newGatedJWKS(t *testing.T, body string) *gatedJWKS {
	s := &gatedJWKS{arrived: make(chan struct{}, 64)}
	s.body.Store(body)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.arrived <- struct{}{}
		if g := s.gate.Load(); g != nil {
			select {
			case <-*g:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte(s.body.Load().(string)))
	}))
	t.Cleanup(s.Close)
	return s
}

// hold makes the next answers wait; the returned function opens the gate.
func (s *gatedJWKS) hold(t *testing.T) (open func()) {
	g := make(chan struct{})
	s.gate.Store(&g)
	var once sync.Once
	open = func() { once.Do(func() { close(g) }) }
	t.Cleanup(open) // before the server closes: cleanups run last-in first-out
	return open
}

// A fetch in flight holds back no caller beyond its own context, serves every
// caller that waits for it with one request, and never lets a caller use the
// set it replaces once that set is due (the refresh interval has passed).
func TestJWKSFetchInFlight(t *testing.T) {
	k2 := jwkOf(t, key(t, 2), "k-2")
	k3 := jwkOf(t, key(t, 3), "k-3")
	srv := newGatedJWKS(t, jwksOf(t, k2))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"first fetch", "refresh of a due set"} {
		t.Run(phase, func(t *testing.T) {
			if phase != "first fetch" {
				if _, err := j.Key(bg, "k-2"); err != nil {
					t.Fatal(err)
				}
				srv.body.Store(jwksOf(t, k3))
				clk.Advance(2 * time.Minute)
			}
			for len(srv.arrived) > 0 {
				<-srv.arrived
			}
			before := srv.hits.Load()
			open := srv.hold(t)
			want := map[string]string{"first fetch": "k-2", "refresh of a due set": "k-3"}[phase]
			leader := make(chan error, 1)
			go func() {
				got, err := j.Key(bg, want)
				if err == nil && got.Kid != want {
					err = errors.New("served " + got.Kid)
				}
				leader <- err
			}()
			<-srv.arrived

			// A caller whose context ends returns with that error while the
			// fetch is slow, and is not served the set being replaced.
			ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
			defer cancel()
			impatient := make(chan error, 1)
			go func() {
				_, err := j.Key(ctx, "k-2")
				impatient <- err
			}()
			select {
			case err := <-impatient:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("caller with an ended context: %v, want its deadline", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("a caller waited past its context for another caller's fetch")
			}

			// Callers that wait share the one fetch.
			var wg sync.WaitGroup
			errs := make(chan error, 16)
			for i := range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if i%2 == 0 {
						got, err := j.Key(bg, want)
						if err == nil && got.Kid != want {
							err = errors.New("served " + got.Kid)
						}
						errs <- err
						return
					}
					if _, err := j.RSAKey(bg, want); !isUnknownKey(err) {
						errs <- errors.New("RSA lookup: " + errString(err))
						return
					}
					errs <- nil
				}()
			}
			time.Sleep(20 * time.Millisecond) // let them reach the wait
			open()
			if err := <-leader; err != nil {
				t.Fatal(err)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := srv.hits.Load() - before; got != 1 {
				t.Fatalf("%d fetches, want 1", got)
			}
			srv.gate.Store(nil)
		})
	}
}

// A caller whose own context ends while it runs the fetch has not seen the
// fetch fail: it gets its context's error, the source does not fail for the
// refresh interval, and a caller that waited, or the next one, fetches.
func TestJWKSFetchCanceled(t *testing.T) {
	srv := newGatedJWKS(t, jwksOf(t, jwkOf(t, key(t, 2), "k-2")))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// A canceled caller that runs the fetch alone: the next caller, inside
	// the interval, fetches again and is served.
	srv.hold(t)
	ctx, cancel := context.WithCancel(bg)
	leader := make(chan error, 1)
	go func() {
		_, err := j.Key(ctx, "k-2")
		leader <- err
	}()
	<-srv.arrived
	cancel()
	if err := waitErr(t, leader); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: %v, want its context's error", err)
	}
	srv.gate.Store(nil)
	if got, err := j.Key(bg, "k-2"); err != nil || got.Kid != "k-2" {
		t.Fatalf("after a canceled fetch: %v %v", got, err)
	}
	<-srv.arrived

	// A canceled caller with callers waiting on its fetch: one of them
	// fetches in its place and all are served.
	clk.Advance(2 * time.Minute)
	open := srv.hold(t)
	ctx, cancel = context.WithCancel(bg)
	go func() {
		_, err := j.Key(ctx, "k-2")
		leader <- err
	}()
	<-srv.arrived
	waiters := make(chan error, 4)
	for range 4 {
		go func() {
			got, err := j.Key(bg, "k-2")
			if err == nil && got.Kid != "k-2" {
				err = errors.New("served " + got.Kid)
			}
			waiters <- err
		}()
	}
	time.Sleep(20 * time.Millisecond) // let them reach the wait
	before := srv.hits.Load()
	cancel()
	if err := waitErr(t, leader); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: %v, want its context's error", err)
	}
	<-srv.arrived // a waiter's own fetch
	open()
	for range 4 {
		if err := waitErr(t, waiters); err != nil {
			t.Fatalf("waiter: %v", err)
		}
	}
	if got := srv.hits.Load() - before; got != 1 {
		t.Fatalf("%d fetches after the cancellation, want 1", got)
	}
	srv.gate.Store(nil)
}

// A fetch that fails, by an HTTP error or a key set that is not one, stands
// for the refresh interval: no caller fetches again before it ends.
func TestJWKSFailedFetchStands(t *testing.T) {
	good := jwksOf(t, jwkOf(t, key(t, 2), "k-2"))
	for name, fail := range map[string]func(*jwksServer){
		"HTTP 500":    func(s *jwksServer) { s.code.Store(500) },
		"not a JWKS":  func(s *jwksServer) { s.body.Store(`{"keys":"none"}`) },
		"not JSON":    func(s *jwksServer) { s.body.Store("<html>") },
		"no keys key": func(s *jwksServer) { s.body.Store(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := newJWKS(t, good)
			clk := clock.NewFake(time.Unix(nowSec, 0))
			j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			fail(srv)
			if _, err := j.Key(bg, "k-2"); err == nil || isUnknownKey(err) {
				t.Fatalf("failed fetch: %v", err)
			}
			srv.code.Store(200)
			srv.body.Store(good)
			clk.Advance(59 * time.Second)
			if _, err := j.Key(bg, "k-2"); err == nil || isUnknownKey(err) {
				t.Fatalf("within the interval after a failed fetch: %v", err)
			}
			if srv.hits.Load() != 1 {
				t.Fatalf("%d fetches within the interval, want 1", srv.hits.Load())
			}
			clk.Advance(time.Second)
			if _, err := j.Key(bg, "k-2"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func waitErr(t *testing.T, c chan error) error {
	t.Helper()
	select {
	case err := <-c:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("a caller did not return")
		return nil
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
