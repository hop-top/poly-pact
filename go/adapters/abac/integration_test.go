package abac_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core/clock"
)

// TestIntegration runs the ABAC cases whose PDP runs assets/policy.rego
// against a real OPA server (the integration tier of the cases README). It
// is gated by PACT_TEST_OPA_URL, the HTTPS origin of an OPA server that
// loaded the policy with decision logging enabled; PACT_TEST_OPA_CA names the
// PEM file of the certificate authority of its TLS certificate. OPA chooses
// the decision_id, so the test checks that the decision names one and
// compares the effect, the obligations and the policy revision.
func TestIntegration(t *testing.T) {
	base := os.Getenv("PACT_TEST_OPA_URL")
	if base == "" {
		t.Skip("PACT_TEST_OPA_URL is not set")
	}
	client := &http.Client{}
	if caFile := os.Getenv("PACT_TEST_OPA_CA"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("%s holds no certificate", caFile)
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "abac")
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "ABAC-") || c.Expect.Function != "authorize_native" {
			continue
		}
		var head struct {
			PDP struct {
				Policy string `json:"policy"`
			} `json:"pdp"`
		}
		if err := json.Unmarshal(c.NativeState, &head); err != nil || head.PDP.Policy == "" {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) { runIntegrationCase(t, c, base, client) })
	}
	if ran == 0 {
		t.Fatal("no case runs against the policy")
	}
}

func runIntegrationCase(t *testing.T, c adaptertest.Case, base string, client *http.Client) {
	now := int64(1792080000)
	if c.Now != nil {
		now = *c.Now
	}
	clk := clock.NewFake(time.Unix(now, 0))
	hooks := &adaptertest.Hooks{}
	w, err := loadWorld(t, c.NativeState, hooks)
	if err != nil {
		t.Fatal(err)
	}
	rt := client.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	w.pdp.URL = base
	w.pdp.Client = &http.Client{Transport: firing{rt: rt, hooks: hooks}, CheckRedirect: client.CheckRedirect}
	a, err := integrationAdapter(t, w, clk, hooks)
	if err != nil {
		t.Fatal(err)
	}
	k := c.Call
	p := adapter.Principal{
		ID:              k.Principal.ID,
		Realm:           adapter.Realm{TenantID: k.Principal.Realm.TenantID, EnvironmentID: k.Principal.Realm.EnvironmentID},
		Workload:        adapter.Workload(k.Principal.Workload),
		Mechanism:       adapter.Mechanism(k.Principal.Mechanism),
		AuthenticatedAt: clk.Now(),
		Attributes:      k.Principal.Attributes,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := a.AuthorizeNative(ctx, p, *k.Operation)
	queried := slices.Contains(hooks.Fired(), hookPDP)
	if slices.Contains(c.Expect.MustNotCall, hookPDP) && queried {
		t.Error("the adapter queried the PDP; the case requires that it did not")
	}
	if c.Expect.Outcome == "error" {
		if code, _ := adapter.CodeOf(err); err == nil || string(code) != c.Expect.ReasonCode {
			t.Errorf("AuthorizeNative = %s, %v; want an error with %s", d.Effect, err, c.Expect.ReasonCode)
		}
		return
	}
	if err != nil {
		t.Fatalf("AuthorizeNative: %v", err)
	}
	if string(d.Effect) != c.Expect.Outcome {
		t.Errorf("effect %s, want %s", d.Effect, c.Expect.Outcome)
	}
	if queried && d.SourceRef == "" {
		t.Error("the decision names no decision_id")
	}
	want := c.Expect.Decision
	if want == nil {
		return
	}
	if want.PolicyRevision != "" && d.PolicyRevision != want.PolicyRevision {
		t.Errorf("policy revision %q, want %q", d.PolicyRevision, want.PolicyRevision)
	}
	if want.Obligations != nil {
		got, _ := json.Marshal(obligationsJSON(d.Obligations))
		exp, _ := json.Marshal(*want.Obligations)
		if !jsonSame(got, exp) {
			t.Errorf("obligations %s, want %s", got, exp)
		}
	}
}

// obligationsJSON is the case form of obligations.
func obligationsJSON(obs []adapter.Obligation) []adaptertest.ObligationJSON {
	out := []adaptertest.ObligationJSON{}
	for _, o := range obs {
		out = append(out, adaptertest.ObligationJSON{ID: o.ID, Attributes: o.Attributes})
	}
	return out
}

// jsonSame compares two JSON texts as data.
func jsonSame(a, b []byte) bool {
	va, errA := decodeJSON(a)
	vb, errB := decodeJSON(b)
	if errA != nil || errB != nil {
		return false
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return string(ja) == string(jb)
}

// firing is a transport that fires the PDP hook for each request it sends.
type firing struct {
	rt    http.RoundTripper
	hooks *adaptertest.Hooks
}

func (f firing) RoundTrip(r *http.Request) (*http.Response, error) {
	f.hooks.Fire(hookPDP)
	return f.rt.RoundTrip(r)
}
