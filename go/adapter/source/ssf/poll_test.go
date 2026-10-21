package ssf_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"hop.top/pact-go/adapter/source/ssf"
)

// pollServer plays a transmitter's poll endpoint: it answers each request
// with the next canned response and records the request bodies.
type pollServer struct {
	*httptest.Server
	mu        sync.Mutex
	responses []string
	status    int
	bodies    []map[string]any
	auth      []string
	ctype     []string
}

func newPollServer(t testing.TB, responses ...string) *pollServer {
	p := &pollServer{responses: responses, status: 200}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || r.Method != http.MethodPost {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		p.bodies = append(p.bodies, m)
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.ctype = append(p.ctype, r.Header.Get("Content-Type"))
		resp := `{"sets":{}}`
		if len(p.responses) > 0 {
			resp, p.responses = p.responses[0], p.responses[1:]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(p.Close)
	return p
}

func setsJSON(t testing.TB, more bool, sets map[string]string) string {
	b, err := json.Marshal(map[string]any{"sets": sets, "moreAvailable": more})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	slices.Sort(out)
	return out
}

// RFC 8936 sections 2.1 to 2.4: poll, then acknowledge what was received in
// the next request, with setErrs for the SETs that are not valid.
func TestPoll(t *testing.T) {
	r := newRig(t)
	good1 := signed(t, claims("j-1", nowSec-30, issSub("u-1"), ssf.EventSessionRevoked, nil))
	good2 := signed(t, claims("j-2", nowSec-20, issSub("nobody"), ssf.EventSessionRevoked, nil)) // unknown subject: still acknowledged
	forged := compact(t, key(t, 3), setHeader(), claims("j-3", nowSec-10, issSub("u-1"), ssf.EventAccountEnabled, nil))
	srv := newPollServer(t,
		setsJSON(t, true, map[string]string{"j-1": good1, "j-2": good2, "j-3": forged, "j-4": good1}), // j-4: key differs from the SET's jti
		setsJSON(t, false, map[string]string{"j-1": good1}),                                           // a redelivery of an applied SET
	)
	p, err := ssf.NewPoller(ssf.PollConfig{URL: srv.URL, Authorization: "Bearer tok", Client: srv.Client(), Receiver: r.rx, MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Poll(bg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Received != 4 || res.Acknowledged != 2 || res.Rejected != 2 || !res.MoreAvailable {
		t.Fatalf("result %+v", res)
	}
	r.wantState(t, principal("7a1f"), ssf.StateSessionRevoked, nowSec-30)
	// The first request carries no acknowledgment, but the limits.
	first := srv.bodies[0]
	if first["maxEvents"] != float64(10) || first["ack"] != nil || srv.auth[0] != "Bearer tok" || srv.ctype[0] != "application/json" {
		t.Fatalf("first request %v auth %q ctype %q", first, srv.auth[0], srv.ctype[0])
	}
	res, err = p.Poll(bg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Received != 1 || res.Acknowledged != 1 || res.MoreAvailable {
		t.Fatalf("second result %+v", res)
	}
	second := srv.bodies[1]
	if got := strs(second["ack"]); !slices.Equal(got, []string{"j-1", "j-2"}) {
		t.Fatalf("ack %v", got)
	}
	errs, _ := second["setErrs"].(map[string]any)
	if len(errs) != 2 {
		t.Fatalf("setErrs %v", errs)
	}
	if e := errs["j-3"].(map[string]any); e["err"] != ssf.CodeInvalidKey || e["description"] == "" {
		t.Fatalf("j-3 %v", e)
	}
	if e := errs["j-4"].(map[string]any); e["err"] != ssf.CodeInvalidRequest {
		t.Fatalf("j-4 %v", e)
	}
	// The redelivered SET is acknowledged again and not applied again.
	if _, err := p.Poll(bg); err != nil {
		t.Fatal(err)
	}
	if got := strs(srv.bodies[2]["ack"]); !slices.Equal(got, []string{"j-1"}) {
		t.Fatalf("ack %v", got)
	}
	if srv.bodies[2]["setErrs"] != nil {
		t.Fatalf("setErrs %v", srv.bodies[2]["setErrs"])
	}
}

// A SET that could not be handled because a dependency is down is neither
// acknowledged nor an error of the SET: the transmitter redelivers it.
func TestPollDependencyFailure(t *testing.T) {
	r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise} })
	r.holds.err = io.ErrUnexpectedEOF
	tok := signed(t, claims("j-1", nowSec-10, issSub("u-1"), ssf.EventCredentialCompromise, map[string]any{"credential_type": "password"}))
	srv := newPollServer(t, setsJSON(t, false, map[string]string{"j-1": tok}))
	p, err := ssf.NewPoller(ssf.PollConfig{URL: srv.URL, Client: srv.Client(), Receiver: r.rx})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Poll(bg); err == nil {
		t.Fatal("dependency failure not reported")
	}
	if _, err := p.Poll(bg); err != nil {
		t.Fatal(err)
	}
	if srv.bodies[1]["ack"] != nil || srv.bodies[1]["setErrs"] != nil {
		t.Fatalf("second request %v", srv.bodies[1])
	}
}

func TestPollTransportErrors(t *testing.T) {
	r := newRig(t)
	if _, err := ssf.NewPoller(ssf.PollConfig{URL: "http://tx.example.com/poll", Receiver: r.rx}); err == nil {
		t.Fatal("http URL accepted")
	}
	if _, err := ssf.NewPoller(ssf.PollConfig{URL: "https://tx.example.com/poll"}); err == nil {
		t.Fatal("no receiver accepted")
	}
	for name, resp := range map[string]string{
		"not json":           `<html>`,
		"sets not an object": `{"sets":[]}`,
		"sets missing":       `{}`,
		"set not a string":   `{"sets":{"j":1}}`,
		"duplicate sets key": `{"sets":{},"sets":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := newPollServer(t, resp)
			p, _ := ssf.NewPoller(ssf.PollConfig{URL: srv.URL, Client: srv.Client(), Receiver: r.rx})
			if _, err := p.Poll(bg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	srv := newPollServer(t, `{"sets":{}}`)
	srv.status = http.StatusUnauthorized
	p, _ := ssf.NewPoller(ssf.PollConfig{URL: srv.URL, Client: srv.Client(), Receiver: r.rx})
	if _, err := p.Poll(bg); err == nil {
		t.Fatal("401 accepted")
	}
}
