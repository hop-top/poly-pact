package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

func TestFindCredentials(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		secrets []string
		want    []string // substrings of the findings; nil for none
	}{
		{"clean", `{"Result":"PASS","ReasonCode":"REQUIREMENT_SATISFIED"}`, nil, nil},
		{"prose that is not a credential", "basic authentication failed; the bearer is unknown", nil, nil},
		{"event kind is not a header", `{"event_kind":"AUTHORIZATION","details":"authorization denied"}`, nil, nil},
		{"literal secret", "failed for tok-alice-7f3a", []string{"tok-alice-7f3a"}, []string{`secret "tok-alice-7f3a"`}},
		{"empty secret is ignored", "anything", []string{""}, nil},
		{"bearer value", "Authorization: Bearer abcdefghijklmnop1234", nil, []string{"authorization value"}},
		{"short bearer is not a value", "Bearer abc", nil, nil},
		{"basic value", "Basic dXNlcjpwYXNzd29yZDEyMzQ1", nil, []string{"authorization value"}},
		{"compact JWS", "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl", nil, []string{"compact JWS"}},
		{"authorization header member", `{"headers":{"authorization":"x"}}`, nil, []string{"credential header as a member name"}},
		{"cookie header member, any case", `{"Cookie" :"x"}`, nil, []string{"credential header as a member name"}},
		{"presentation header member", `{"pact-presentation":"x"}`, nil, []string{"credential header as a member name"}},
		{"private JWK d", `{"kty":"EC","d":"abc"}`, nil, []string{"private JWK parameter"}},
		{"private JWK k", `{"kty":"oct","k":"abc"}`, nil, []string{"private JWK parameter"}},
		{"public JWK", `{"kty":"EC","x":"abc","y":"def"}`, nil, nil},
		{"access token in a URL", "https://e.example/a?access_token=tok-evidence-5c0e8b13", nil, []string{"credential assignment"}},
		{"session cookie value", "session=sess-cookie-93ab1f60", nil, []string{"credential assignment"}},
		{"password", "password=hunter22", nil, []string{"credential assignment"}},
		{"redaction mask in brackets", "access_token=[redacted]", nil, nil},
		{"redaction mask in words", "session=REDACTED password=removed", nil, nil},
		{"redaction mask in stars", "secret=****** api_key=xxxxxxxx", nil, nil},
		{"mask followed by a credential", "access_token=[redacted] session=sess-cookie-93ab1f60", nil, []string{"credential assignment"}},
		{"short value is not a credential", "sid=abc", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findCredentials(tc.text, tc.secrets)
			if len(tc.want) == 0 {
				if len(got) > 0 {
					t.Fatalf("found %q in %q", got, tc.text)
				}
				return
			}
			for _, w := range tc.want {
				ok := false
				for _, g := range got {
					ok = ok || strings.Contains(g, w)
				}
				if !ok {
					t.Errorf("findings %q lack %q", got, w)
				}
			}
		})
	}
}

// leakCase asks for a leak scan of an authenticate_native case that the fake
// answers with err.
func leakCase(secrets ...string) *Case {
	c := authCase(outDenied, Expect{LeakScan: &LeakScan{Secrets: secrets}})
	return c
}

func TestLeakScanOfErrors(t *testing.T) {
	denial := &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	runRows(t, []row{
		{"clean denial", authFake(adapter.Principal{}, denial), leakCase("tok-forged-4e1d7a09"), nil},
		{"token in a wrapping error", authFake(adapter.Principal{}, fmt.Errorf("token tok-forged-4e1d7a09 rejected: %w", denial)),
			leakCase("tok-forged-4e1d7a09"), []string{"error carries a credential", "tok-forged-4e1d7a09"}},
		{"bearer value in a wrapping error", authFake(adapter.Principal{}, fmt.Errorf("Bearer abcdefghijklmnop1234: %w", denial)),
			leakCase(), []string{"authorization value"}},
		{"no scan asked, no scan made", authFake(adapter.Principal{}, fmt.Errorf("token tok-forged-4e1d7a09 rejected: %w", denial)),
			authCase(outDenied, Expect{}), nil},
	})
}

func TestLeakScanOfValues(t *testing.T) {
	scan := &LeakScan{Secrets: []string{"tok-secret-1234"}}

	t.Run("operation", func(t *testing.T) {
		leaky := goodOp()
		leaky.Headers = map[string]string{"authorization": "x"}
		c := mapCase(outMapped, Expect{Operation: &ExpectOperation{}, LeakScan: scan}, Request{})
		wantClean(t, runFake(t, mapFake(goodOp(), nil), c))
		wantFails(t, runFake(t, mapFake(leaky, nil), c), "operation carries a credential")
		leaky.Headers = map[string]string{"x-kind": "tok-secret-1234"}
		wantFails(t, runFake(t, mapFake(leaky, nil), c), `secret "tok-secret-1234"`)
	})

	t.Run("operation error", func(t *testing.T) {
		c := mapCase(outError, Expect{LeakScan: scan}, Request{})
		wantClean(t, runFake(t, mapFake(core.OperationContext{}, adapter.ErrContextMismatch), c))
		wantFails(t, runFake(t, mapFake(core.OperationContext{}, fmt.Errorf("tok-secret-1234 %w", adapter.ErrContextMismatch)), c),
			"MapOperation error carries a credential")
	})

	t.Run("check outcome", func(t *testing.T) {
		c := checkCase("x", outPass, Expect{LeakScan: scan})
		clean := adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "R", SourceRef: "appr-42"}
		leaky := clean
		leaky.SourceRef = "https://e.example/a?access_token=tok-secret-1234"
		wantClean(t, runFake(t, checkFake(clean), c))
		wantFails(t, runFake(t, checkFake(leaky), c), "CheckContext outcome carries a credential")
	})

	t.Run("claim", func(t *testing.T) {
		c := claimCase(outClaim, Expect{Claim: &ExpectClaim{}, LeakScan: scan})
		leaky := goodClaim()
		leaky.SourceRef = "tok-secret-1234"
		wantClean(t, runFake(t, claimFake(goodClaim(), nil), c))
		wantFails(t, runFake(t, claimFake(leaky, nil), c), "claim carries a credential")
	})

	t.Run("decision", func(t *testing.T) {
		c := authzCase(outDeny, Expect{LeakScan: scan})
		wantClean(t, runFake(t, authzFake(adapter.Decision{Effect: adapter.EffectDeny, SourceID: "policy-1"}, nil), c))
		wantFails(t, runFake(t, authzFake(adapter.Decision{Effect: adapter.EffectDeny, Reason: "tok-secret-1234", SourceID: "policy-1"}, nil), c),
			"decision carries a credential")
	})

	t.Run("principal", func(t *testing.T) {
		c := authCase(outAuthenticated, Expect{Principal: &ExpectPrincipal{}, LeakScan: scan})
		p := goodPrincipal()
		wantClean(t, runFake(t, authFake(p, nil), c))
		p.Attributes = map[string]any{"token": "tok-secret-1234"}
		wantFails(t, runFake(t, authFake(p, nil), c), "principal carries a credential")
	})

	t.Run("signed outcome, decoded", func(t *testing.T) {
		c := recordCase(outSigned, Expect{LeakScan: &LeakScan{Secrets: []string{"tok-secret-1234"}}}, core.EventExecution, core.OutcomeSuccess)
		wantClean(t, runFake(t, signedFake(nil), c))
		// A credential in the payload is base64url in the JWS string, so only
		// the decoded payload shows it.
		wantFails(t, runFake(t, signedFake(func(p *parts) { p.rep.Details = "rejected: tok-secret-1234" }), c),
			"signed outcome segment 1 carries a credential")
		wantFails(t, runFake(t, signedFake(func(p *parts) { p.rep.Details = "Authorization: Bearer abcdefghijklmnop1234" }), c),
			"authorization value")
		wantFails(t, runFake(t, signedFake(func(p *parts) { p.rep.EvidenceRefs = []string{"https://e.example/x?access_token=abcdef123456"} }), c),
			"credential assignment")
		// A masked value is not a credential.
		wantClean(t, runFake(t, signedFake(func(p *parts) { p.rep.Details = "Authorization: [redacted] access_token=[redacted]" }), c))
	})

	t.Run("no visibility declaration", func(t *testing.T) {
		c := recordCase(outNoVisibility, Expect{LeakScan: scan}, core.EventExecution, core.OutcomeSuccess)
		wantClean(t, runFake(t, recordFake(adapter.NoVisibility{Reason: "cannot see"}, nil), c))
		wantFails(t, runFake(t, recordFake(adapter.NoVisibility{Reason: "cannot see tok-secret-1234"}, nil), c),
			"declaration carries a credential")
	})
}

func TestLeakScanRunsOnEveryError(t *testing.T) {
	// One error per function, each carrying the secret.
	secretErr := errors.New("tok-secret-1234")
	scan := &LeakScan{Secrets: []string{"tok-secret-1234"}}
	f := &fake{
		auth: func(context.Context, *http.Request) (adapter.Principal, error) { return adapter.Principal{}, secretErr },
		bind: func(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
			return adapter.AgentBinding{}, secretErr
		},
		claim: func(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error) {
			return adapter.NativeClaim{}, secretErr
		},
		authz: func(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
			return adapter.Decision{}, secretErr
		},
		record: func(context.Context, adapter.Observation) (adapter.Recorded, error) { return nil, secretErr },
	}
	for name, c := range map[string]*Case{
		"authenticate": authCase(outError, Expect{LeakScan: scan}),
		"binding":      bindCase(outError, Expect{LeakScan: scan}),
		"claim":        claimCase(outError, Expect{LeakScan: scan}),
		"authorize":    authzCase(outError, Expect{LeakScan: scan}),
		"record":       recordCase(outError, Expect{LeakScan: scan}, core.EventExecution, core.OutcomeSuccess),
	} {
		t.Run(name, func(t *testing.T) {
			wantFails(t, runFake(t, f, c), "error carries a credential")
		})
	}
}
