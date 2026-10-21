package contract_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

const (
	draftPath    = "../../spec/v1.0/draft.md"
	fixturesRoot = "../../spec/v1.0/fixtures"
)

// Values of draft Appendix B.4 and of the fixture configuration of
// spec/v1.0/fixtures/admission/valid, written out here from the draft text.
const (
	b4Time      = 1792080000
	b4Publisher = "https://trust.example/issuers/finance"
	b4Agent     = "https://identity.example/agents/invoice-assistant"
	b4Gateway   = "https://gateway.example/finance"
	b4Tenant    = "acme"
	b4Env       = "https://gateway.example/environments/finance"
	b4HolderJKT = core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M")
	b4Principal = "https://identity.example/principals/alice"
	b4Operator  = "https://identity.example/operators/acme"
	b4Base      = "finance-base-3"
	b4PolicyDig = core.Digest("mIu2mtBMHPAf6CgJkuwuDsUWhs9bu-Wkenl4QlrcQAQ")
	b4ArtDig    = core.Digest("Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0")
	b4OpDigest  = core.Digest("R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0")
	b4IntDigest = core.Digest("t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M")
)

var b4Realm = adapter.Realm{TenantID: b4Tenant, EnvironmentID: b4Env}

func at(sec int64) time.Time { return time.Unix(sec, 0) }

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func fixture(t testing.TB, rel string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
}

func compactOf(t testing.TB, rel string) string {
	t.Helper()
	return strings.TrimSpace(string(fixture(t, rel)))
}

// draftBlock returns the first json block under the heading "### <section> ".
func draftBlock(t testing.TB, section string) []byte {
	t.Helper()
	re := regexp.MustCompile(`(?m)^### ` + regexp.QuoteMeta(section) + ` [^\n]*\n(?:[^\n#][^\n]*\n|\n)*?` + "```json\n" + `((?s:.*?))\n` + "```\n")
	m := re.FindSubmatch(readFile(t, draftPath))
	if m == nil {
		t.Fatalf("draft has no json block under %s", section)
	}
	return m[1]
}

func canonical(t testing.TB, b []byte) string {
	t.Helper()
	c, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return string(c)
}

func decodeStrict(t testing.TB, b []byte, v any) {
	t.Helper()
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// scalarKey is the P-256 test key of private scalar n
// (spec/v1.0/fixtures/keys/README.md).
func scalarKey(t testing.TB, n byte) *ecdsa.PrivateKey {
	t.Helper()
	d := make([]byte, 32)
	d[31] = n
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixtureKeySet(t testing.TB, names ...string) *jws.KeySet {
	t.Helper()
	var keys []jws.JWK
	for _, n := range names {
		k, err := jws.ParseJWK(fixture(t, "keys/"+n+".jwk.json"))
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		keys = append(keys, k)
	}
	s, err := jws.NewKeySet(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// issuerSigner signs as the requirement publisher of the fixtures: the
// issuer key, P-256 scalar 2, kid test-issuer-key-1.
func issuerSigner(t testing.TB) contract.ES256Signer {
	t.Helper()
	return contract.ES256Signer{Kid: "test-issuer-key-1", Key: scalarKey(t, 2)}
}

// b4Verifier trusts the issuer key for the B.4 publisher, with the
// baseline skew of the fixture configuration.
func b4Verifier(t testing.TB) contract.Verifier {
	t.Helper()
	return contract.Verifier{
		Publishers: map[string]*jws.KeySet{b4Publisher: fixtureKeySet(t, "issuer")},
		Skew:       5 * time.Second,
	}
}

func b4Expect() contract.Expect {
	return contract.Expect{AgentID: b4Agent, Audience: b4Gateway, Realm: b4Realm}
}

func b4Policy() contract.Policy {
	return contract.Policy{BaseRevision: b4Base, LearningPolicyDigest: b4PolicyDig, LearningArtifactDigest: b4ArtDig}
}

// b4Requirements are the effective requirements of the B.4 contract; the
// conservative set is that of the B.9 learning policy.
func b4Requirements(t testing.TB) contract.Requirements {
	t.Helper()
	var c core.RequirementContract
	decodeStrict(t, draftBlock(t, "B.4"), &c)
	return contract.Requirements{
		Policy:          b4Policy(),
		SelectedSet:     "supervised",
		ConservativeSet: "supervised",
		FieldRules:      c.FieldRules,
		ContextChecks:   c.ContextChecks,
		Mode:            core.ModeEnforced,
	}
}

// b4Request is the contract request of the B.2 intent and B.3 operation.
func b4Request(t testing.TB) core.ContractRequest {
	t.Helper()
	req := core.ContractRequest{AgentID: b4Agent, HolderJKT: b4HolderJKT}
	decodeStrict(t, draftBlock(t, "B.2"), &req.Intent)
	decodeStrict(t, draftBlock(t, "B.3"), &req.Operation)
	return req
}

// b4Auth is native context that authenticated alice in the B.4 realm with
// the enrolled B.4 agent binding.
func b4Auth() contract.Authenticated {
	return contract.Authenticated{
		Principal: adapter.Principal{ID: b4Principal, Realm: b4Realm, Workload: "workload:invoice-assistant", AuthenticatedAt: at(b4Time)},
		Binding: adapter.AgentBinding{
			AgentID: b4Agent, OperatorID: b4Operator, HolderJKT: b4HolderJKT, Status: adapter.BindingActive,
			ObservedAt: at(b4Time), StatusCheckedAt: at(b4Time), SourceID: "enrollment",
		},
	}
}

func newPublisher(t testing.TB, store contract.ReplayStore) *contract.Publisher {
	t.Helper()
	return &contract.Publisher{
		Issuer: b4Publisher, Audience: b4Gateway, Realm: b4Realm,
		Signer: issuerSigner(t), Replay: store,
	}
}

// resign returns compact with its payload replaced by payload and signed
// again by key under the same header, so that a test can present a payload
// the publisher signed with a defect.
func resign(t testing.TB, header, payload []byte, key *ecdsa.PrivateKey) string {
	t.Helper()
	var h struct {
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatal(err)
	}
	s, err := jws.Sign(jws.Header{Typ: h.Typ, Kid: h.Kid}, payload, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func segment(t testing.TB, compact string, i int) []byte {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// editPayload decodes the payload of compact into a generic object, applies
// edit, and re-encodes it.
func editPayload(t testing.TB, compact string, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(segment(t, compact, 1)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var bg = context.Background()
