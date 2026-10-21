package holder_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/holder"
)

var financeMapping = binding.Config{
	Origin:                "https://gateway.example",
	HeaderAllowlist:       []string{"if-match", "x-dry-run"},
	HeaderNormalizationID: "finance-header-normalization-1",
	MappingVersion:        "finance-http-1",
	MaxBody:               1 << 20,
}

// TestOperationFromRequest: the outgoing request of the B.3 invoice read
// maps to the B.3 operation, whose object_digest is the one the B.4
// contract binds (draft 10.2).
func TestOperationFromRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://gateway.example/invoices/INV-1042", nil)
	if err != nil {
		t.Fatal(err)
	}
	op, err := holder.OperationFromRequest(financeMapping, req, "invoice-read-operation-0001", bEnv, bPrincipal, "invoice.read",
		[]string{"https://invoices.example/invoices/INV-1042"})
	if err != nil {
		t.Fatalf("OperationFromRequest: %v", err)
	}
	if got := mustDigest(t, op); got != bOpDigest {
		t.Fatalf("operation digest %s, want %s: %+v", got, bOpDigest, op)
	}
}

// TestOperationFromRequestBody: the body is hashed as sent and stays
// readable for sending; headers follow the allowlist; the request-target is
// the one the client writes, so an ambiguous encoding is refused.
func TestOperationFromRequestBody(t *testing.T) {
	body := `{"amount":"12.00"}`
	req, err := http.NewRequest(http.MethodPost, "https://Gateway.Example:443/invoices/INV-1042/pay?b=2&a=1", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dry-Run", "true")
	req.Header.Set("Authorization", "Bearer secret")
	op, err := holder.OperationFromRequest(financeMapping, req, "op-2", bEnv, bPrincipal, "invoice.pay", []string{"https://invoices.example/invoices/INV-1042"})
	if err != nil {
		t.Fatalf("OperationFromRequest: %v", err)
	}
	if op.Method != "POST" || op.TargetURI != "https://gateway.example/invoices/INV-1042/pay?b=2&a=1" {
		t.Fatalf("method %s target %s", op.Method, op.TargetURI)
	}
	if op.BodyDigest != digest.BytesDigest([]byte(body)) {
		t.Fatal("body digest")
	}
	if len(op.Headers) != 2 || op.Headers["x-dry-run"] != "true" || op.Headers["content-type"] != "application/json" {
		t.Fatalf("headers %v", op.Headers)
	}
	if op.OperationID != "op-2" || op.EnvironmentID != bEnv || op.PrincipalID != bPrincipal || op.Action != "invoice.pay" {
		t.Fatalf("ids %+v", op)
	}
	sent, err := io.ReadAll(req.Body)
	if err != nil || string(sent) != body {
		t.Fatalf("body after mapping %q, %v", sent, err)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody unset")
	}
	again, _ := req.GetBody()
	if b, _ := io.ReadAll(again); string(b) != body {
		t.Fatalf("GetBody %q", b)
	}

	bad, err := http.NewRequest(http.MethodGet, "https://gateway.example/invoices/%7Einv", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = holder.OperationFromRequest(financeMapping, bad, "op-3", bEnv, bPrincipal, "invoice.read", nil)
	wantErr(t, err, holder.ErrInvalidMessage)
	var re *binding.RequestError
	if !errors.As(err, &re) || re.Rule != binding.RuleEncodedUnreserved {
		t.Fatalf("error %v, want rule %s", err, binding.RuleEncodedUnreserved)
	}
	_, err = holder.OperationFromRequest(financeMapping, nil, "op-4", bEnv, bPrincipal, "invoice.read", nil)
	wantErr(t, err, holder.ErrInvalidMessage)
}
