package binding_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
)

// operationDigestB3 is the operation_digest of draft Appendix B.4 and B.7,
// object_digest of the B.3 operation context.
const operationDigestB3 core.Digest = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"

// vectorsFile holds the B.3 object as the digest vector "operation-b3".
var vectorsFile = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures", "vectors", "digest", "appendix-b.json")

// appendixB3 returns the B.3 operation context text and its expected digest
// from the digest vectors.
func appendixB3(t *testing.T) (json.RawMessage, core.Digest) {
	t.Helper()
	b, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		ID             string          `json:"id"`
		Input          json.RawMessage `json:"input"`
		ExpectedDigest core.Digest     `json:"expected_digest"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(vectors, func(v struct {
		ID             string          `json:"id"`
		Input          json.RawMessage `json:"input"`
		ExpectedDigest core.Digest     `json:"expected_digest"`
	}) bool {
		return v.ID == "operation-b3"
	})
	if i < 0 {
		t.Fatalf("%s has no vector operation-b3", vectorsFile)
	}
	return vectors[i].Input, vectors[i].ExpectedDigest
}

// TestAppendixB3: the request of the Appendix B example, sent to a real
// server with credentials and a presentation header, binds to the B.3
// operation context and its digest once the caller sets operation_id and
// environment_id.
func TestAppendixB3(t *testing.T) {
	want, wantDigest := appendixB3(t)
	if wantDigest != operationDigestB3 {
		t.Fatalf("vector digest %q, draft B.4 prints %q", wantDigest, operationDigestB3)
	}

	op, err := bind(t, config(), "GET /invoices/INV-1042 HTTP/1.1\r\n"+
		"Host: gateway.example\r\n"+
		"Authorization: Bearer native-token\r\n"+
		"PACT-Presentation: eyJhbGciOiJFUzI1NiJ9.e30.c2ln\r\n"+
		"Accept: application/json\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if op.OperationID != "" || op.EnvironmentID != "" {
		t.Fatalf("FromRequest set operation_id %q and environment_id %q; the caller owns them", op.OperationID, op.EnvironmentID)
	}
	op.OperationID = "invoice-read-operation-0001"
	op.EnvironmentID = "https://gateway.example/environments/finance"

	got, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	gotC, err := jcs.Canonicalize(got)
	if err != nil {
		t.Fatal(err)
	}
	wantC, err := jcs.Canonicalize(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotC, wantC) {
		t.Fatalf("operation context\n got %s\nwant %s", gotC, wantC)
	}
	d, err := digest.ObjectDigest(op)
	if err != nil {
		t.Fatal(err)
	}
	if d != operationDigestB3 {
		t.Fatalf("object_digest %q, want %q", d, operationDigestB3)
	}
}

// TestCallerValues: principal, action and resources are the caller's, and the
// resources are copied.
func TestCallerValues(t *testing.T) {
	res := []string{"https://invoices.example/invoices/1", "https://invoices.example/invoices/2"}
	op, err := binding.FromRequest(config(), get(t, "/x"), "https://identity.example/principals/bob", "invoice.list", res)
	if err != nil {
		t.Fatal(err)
	}
	if op.PrincipalID != "https://identity.example/principals/bob" || op.Action != "invoice.list" {
		t.Fatalf("principal %q action %q", op.PrincipalID, op.Action)
	}
	res[0] = "changed"
	if op.Resources[0] != "https://invoices.example/invoices/1" || len(op.Resources) != 2 {
		t.Fatalf("resources %q share the caller's slice", op.Resources)
	}
}
