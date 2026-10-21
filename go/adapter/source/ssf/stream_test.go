package ssf_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"hop.top/pact-go/adapter/source/ssf"
)

type call struct {
	method, path, query, auth string
	body                      map[string]any
}

// txServer plays a transmitter's stream management API (SSF 1.0 section 8.1).
type txServer struct {
	*httptest.Server
	calls  []call
	status map[string]int
	reply  map[string]string
}

func newTxServer(t testing.TB) *txServer {
	s := &txServer{status: map[string]int{}, reply: map[string]string{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c := call{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization")}
		if len(b) > 0 {
			_ = json.Unmarshal(b, &c.body)
		}
		s.calls = append(s.calls, c)
		code := 200
		if v, ok := s.status[r.Method+" "+r.URL.Path]; ok {
			code = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(s.reply[r.Method+" "+r.URL.Path]))
	}))
	t.Cleanup(s.Close)
	return s
}

const streamJSON = `{"stream_id":"s-1","iss":"https://tx.example.com","aud":["https://rx.example.com/ssf"],
"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example.com/ssf/push"},
"events_supported":["https://schemas.openid.net/secevent/caep/event-type/session-revoked","https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"],
"events_requested":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
"events_delivered":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
"min_verification_interval":30}`

func newTx(t testing.TB, s *txServer) *ssf.Transmitter {
	tx, err := ssf.NewTransmitter(ssf.TransmitterConfig{
		Issuer:                txIssuer,
		ConfigurationEndpoint: s.URL + "/stream",
		StatusEndpoint:        s.URL + "/status",
		VerificationEndpoint:  s.URL + "/verify",
		Authorization:         "Bearer mgmt",
		Client:                s.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// SSF 1.0 sections 8.1.1.1 (create), 8.1.1.2 (read), 8.1.2 (status) and
// 8.1.4.2 (verification).
func TestStreamManagement(t *testing.T) {
	s := newTxServer(t)
	tx := newTx(t, s)
	s.status["POST /stream"] = 201
	s.reply["POST /stream"] = streamJSON
	got, err := tx.CreateStream(bg, ssf.StreamRequest{
		Delivery:        ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: "https://rx.example.com/ssf/push", AuthorizationHeader: "Bearer rx"},
		EventsRequested: []string{ssf.EventSessionRevoked},
		Description:     "pact",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := s.calls[0]
	if c.method != "POST" || c.auth != "Bearer mgmt" {
		t.Fatalf("call %+v", c)
	}
	d := c.body["delivery"].(map[string]any)
	if d["method"] != "urn:ietf:rfc:8935" || d["endpoint_url"] != "https://rx.example.com/ssf/push" || d["authorization_header"] != "Bearer rx" {
		t.Fatalf("delivery %v", d)
	}
	if got.StreamID != "s-1" || got.Issuer != txIssuer || !slices.Equal(got.Audience, []string{rxAud}) || !slices.Equal(got.EventsDelivered, []string{ssf.EventSessionRevoked}) || got.MinVerificationInterval != 30 {
		t.Fatalf("stream %+v", got)
	}
	// Read one stream.
	s.reply["GET /stream"] = streamJSON
	if _, err := tx.Stream(bg, "s-1"); err != nil {
		t.Fatal(err)
	}
	if c := s.calls[1]; c.method != "GET" || c.query != "stream_id=s-1" {
		t.Fatalf("call %+v", c)
	}
	// Status.
	s.reply["GET /status"] = `{"stream_id":"s-1","status":"paused","reason":"maintenance"}`
	st, err := tx.Status(bg, "s-1")
	if err != nil || st != ssf.StatusPaused {
		t.Fatalf("%q %v", st, err)
	}
	s.reply["POST /status"] = `{"stream_id":"s-1","status":"enabled"}`
	st, err = tx.SetStatus(bg, "s-1", ssf.StatusEnabled)
	if err != nil || st != ssf.StatusEnabled {
		t.Fatalf("%q %v", st, err)
	}
	if c := s.calls[3]; c.body["stream_id"] != "s-1" || c.body["status"] != "enabled" {
		t.Fatalf("call %+v", c)
	}
	// Verification: 204.
	s.status["POST /verify"] = 204
	if err := tx.RequestVerification(bg, "s-1", "s-123"); err != nil {
		t.Fatal(err)
	}
	if c := s.calls[4]; c.body["stream_id"] != "s-1" || c.body["state"] != "s-123" {
		t.Fatalf("call %+v", c)
	}
}

func TestStreamErrors(t *testing.T) {
	s := newTxServer(t)
	tx := newTx(t, s)
	t.Run("issuer mismatch", func(t *testing.T) {
		s.status["POST /stream"] = 201
		s.reply["POST /stream"] = `{"stream_id":"s-1","iss":"https://evil.example","aud":"` + rxAud + `","delivery":{"method":"urn:ietf:rfc:8936"},"events_delivered":[]}`
		if _, err := tx.CreateStream(bg, ssf.StreamRequest{}); err == nil {
			t.Fatal("accepted a stream of another issuer (SSF 8.1.1)")
		}
	})
	t.Run("audience as a string", func(t *testing.T) {
		s.reply["POST /stream"] = `{"stream_id":"s-1","iss":"` + txIssuer + `","aud":"` + rxAud + `","delivery":{"method":"urn:ietf:rfc:8936"},"events_delivered":[]}`
		st, err := tx.CreateStream(bg, ssf.StreamRequest{})
		if err != nil || !slices.Equal(st.Audience, []string{rxAud}) {
			t.Fatalf("%+v %v", st, err)
		}
	})
	t.Run("no stream id", func(t *testing.T) {
		s.reply["POST /stream"] = `{"iss":"` + txIssuer + `","aud":"` + rxAud + `","delivery":{"method":"urn:ietf:rfc:8936"},"events_delivered":[]}`
		if _, err := tx.CreateStream(bg, ssf.StreamRequest{}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("status codes", func(t *testing.T) {
		for _, code := range []int{400, 401, 403, 404, 409, 429, 500} {
			s.status["POST /stream"] = code
			s.reply["POST /stream"] = `{}`
			if _, err := tx.CreateStream(bg, ssf.StreamRequest{}); err == nil {
				t.Fatalf("%d accepted", code)
			}
		}
		s.status["POST /verify"] = 429
		if err := tx.RequestVerification(bg, "s-1", ""); err == nil {
			t.Fatal("429 accepted")
		}
	})
	t.Run("unknown status value", func(t *testing.T) {
		s.status["GET /status"] = 200
		s.reply["GET /status"] = `{"stream_id":"s-1","status":"flying"}`
		if _, err := tx.Status(bg, "s-1"); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("insecure endpoints", func(t *testing.T) {
		_, err := ssf.NewTransmitter(ssf.TransmitterConfig{Issuer: txIssuer, ConfigurationEndpoint: "http://tx.example.com/stream"})
		if err == nil {
			t.Fatal("http endpoint accepted")
		}
	})
}
