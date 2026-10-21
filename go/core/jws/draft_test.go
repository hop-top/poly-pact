package jws_test

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

func readDraft(t testing.TB) string {
	t.Helper()
	return string(readFile(t, draftPath))
}

// section returns the draft text from the heading start up to the heading
// end.
func section(t testing.TB, draft, start, end string) string {
	t.Helper()
	i := strings.Index(draft, start)
	if i < 0 {
		t.Fatalf("draft has no %q", start)
	}
	j := strings.Index(draft[i:], end)
	if j < 0 {
		t.Fatalf("draft has no %q after %q", end, start)
	}
	return draft[i : i+j]
}

// fenced returns the body of the first fenced block of the given language
// after marker.
func fenced(t testing.TB, text, marker, lang string) string {
	t.Helper()
	i := strings.Index(text, marker)
	if i < 0 {
		t.Fatalf("no %q", marker)
	}
	rest := text[i:]
	open := "```" + lang + "\n"
	j := strings.Index(rest, open)
	if j < 0 {
		t.Fatalf("no %s block after %q", lang, marker)
	}
	body := rest[j+len(open):]
	k := strings.Index(body, "\n```")
	if k < 0 {
		t.Fatalf("unterminated %s block after %q", lang, marker)
	}
	return body[:k]
}

func appendixC(t testing.TB) string {
	return section(t, readDraft(t), "## Appendix C.", "## Appendix D.")
}

func appendixCCompact(t testing.TB) string {
	return strings.TrimSpace(fenced(t, appendixC(t), "Exact compact evidence JWS:", "text"))
}

func appendixB5(t testing.TB) string {
	return fenced(t, readDraft(t), "### B.5 Runtime evidence", "json")
}

// signerRoles maps the "Required signer" cells of the draft 7.3 table to
// roles. A changed cell fails TestTypTableMatchesDraft until it is mapped.
var signerRoles = map[string]jws.Role{
	"Gateway-authorized requirement publisher":           jws.RoleRequirementPublisher,
	"Issuer authorized for its claim paths and scope":    jws.RoleIssuer,
	"Enrolled agent holder key":                          jws.RoleHolder,
	"Gateway-authorized validator":                       jws.RoleValidator,
	"Authorized reporter for the observation type":       jws.RoleReporter,
	"Authorized reputation service":                      jws.RoleReputationService,
	"Native administrator or delegated policy authority": jws.RolePolicyAuthority,
	"Authorized learning controller":                     jws.RoleLearningController,
	"Controller authorized for that transition":          jws.RoleLearningController,
}

func TestTypTableMatchesDraft(t *testing.T) {
	table := section(t, readDraft(t), "### 7.3 Artifact types and claims", "### 7.4")
	rows := regexp.MustCompile("(?m)^\\| ([^|]+?) \\| `([^`]+)` \\| ([^|]+?) \\|$").FindAllStringSubmatch(table, -1)
	if len(rows) == 0 {
		t.Fatal("no typ rows found in draft 7.3")
	}
	var typs []string
	for _, r := range rows {
		typ, signer := r[2], r[3]
		typs = append(typs, typ)
		want, ok := signerRoles[signer]
		if !ok {
			t.Errorf("draft 7.3 signer %q (typ %s) has no role mapping", signer, typ)
			continue
		}
		got, ok := jws.TypRole(typ)
		if !ok || got != want {
			t.Errorf("TypRole(%q) = %q, %v; draft 7.3 requires %q (%s)", typ, got, ok, want, signer)
		}
	}
	if got := jws.Typs(); !slices.Equal(got, typs) {
		t.Errorf("Typs() = %q, want the draft 7.3 order %q", got, typs)
	}
	for _, typ := range []string{"", "JWT", "pact-profile+jwt", "pact-evidence+JWT"} {
		if r, ok := jws.TypRole(typ); ok {
			t.Errorf("TypRole(%q) = %q, want not found", typ, r)
		}
	}
}

func TestDefaultMaxCompactBytesMatchesDraft(t *testing.T) {
	// Section 20.1: the frame minimum covers an encoded 256 KiB payload plus
	// the JOSE header and signature.
	if !strings.Contains(readDraft(t), "349526 + 10922 = 360448") || jws.DefaultMaxCompactBytes != 360448 {
		t.Errorf("DefaultMaxCompactBytes = %d; the draft 20.1 frame minimum is 360448", jws.DefaultMaxCompactBytes)
	}
}

// TestAppendixCKeys derives the public keys of P-256 scalars 1 (holder) and
// 2 (issuer) and compares them with the JWKs printed in Appendix C, and the
// holder thumbprint with the printed holder_jkt.
func TestAppendixCKeys(t *testing.T) {
	c := appendixC(t)
	issuerPrinted := fenced(t, c, "Issuer public JWK", "json")
	holderPrinted := fenced(t, c, "Holder public JWK and thumbprint", "json")
	var hp struct {
		JWK       map[string]string `json:"jwk"`
		HolderJKT core.Digest       `json:"holder_jkt"`
	}
	if err := strictjson.Unmarshal([]byte(holderPrinted), strictjson.Limits{}, &hp); err != nil {
		t.Fatal(err)
	}
	ip, err := jws.ParseJWK([]byte(issuerPrinted))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		scalar byte
		x, y   string
	}{
		{1, hp.JWK["x"], hp.JWK["y"]},
		{2, ip.X, ip.Y},
	} {
		k, err := jws.PublicJWK(&scalarKey(t, c.scalar).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if k.X != c.x || k.Y != c.y {
			t.Errorf("scalar %d derives x=%s y=%s, Appendix C prints x=%s y=%s", c.scalar, k.X, k.Y, c.x, c.y)
		}
		if c.scalar == 1 {
			tp, err := jws.Thumbprint(k)
			if err != nil || tp != hp.HolderJKT || hp.HolderJKT != holderJKT {
				t.Errorf("holder thumbprint %q (%v), Appendix C holder_jkt %q", tp, err, hp.HolderJKT)
			}
		}
	}
	if ip.Kid != "test-issuer-key-1" {
		t.Errorf("Appendix C issuer kid %q", ip.Kid)
	}
}

// TestAppendixCJWS verifies the exact compact evidence JWS of Appendix C
// under the printed issuer JWK and checks every expectation the appendix
// states.
func TestAppendixCJWS(t *testing.T) {
	c := appendixC(t)
	issuer, err := jws.ParseJWK([]byte(fenced(t, c, "Issuer public JWK", "json")))
	if err != nil {
		t.Fatal(err)
	}
	res := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleIssuer: keySet(t, issuer)}}
	p, err := jws.Verifier{Keys: res, Typ: jws.TypEvidence}.Verify(appendixCCompact(t))
	if err != nil {
		t.Fatalf("Appendix C JWS: %v", err)
	}
	if p.Header.Typ != "pact-evidence+jwt" || p.Role != jws.RoleIssuer {
		t.Errorf("typ %q role %q", p.Header.Typ, p.Role)
	}
	if b5 := appendixB5(t); !bytes.Equal(p.Payload, []byte(b5)) {
		t.Errorf("payload is not byte for byte the B.5 block:\n%s\nwant\n%s", p.Payload, b5)
	}
	var ev core.Evidence
	if err := strictjson.Unmarshal(p.Payload, core.Defaults().ArtifactJSON(), &ev); err != nil {
		t.Fatalf("decode as Evidence: %v", err)
	}
	if ev.PactVersion != core.Version {
		t.Errorf("pact_version %q, want %q", ev.PactVersion, core.Version)
	}
	if ev.Subject != "https://identity.example/agents/invoice-assistant" {
		t.Errorf("sub %q", ev.Subject)
	}
	if len(ev.Claims) != 1 || ev.Claims[0].Path != "/attributes/runtime/isolation" || string(ev.Claims[0].Value) != `"managed"` {
		t.Errorf("claims %+v", ev.Claims)
	}
	if ev.HolderJKT != holderJKT {
		t.Errorf("holder_jkt %q", ev.HolderJKT)
	}
	// Not under the holder key.
	wrong := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleIssuer: keySet(t, withKid(fixtureJWK(t, "holder"), "test-issuer-key-1"))}}
	_, err = jws.Verify(appendixCCompact(t), wrong)
	wantReason(t, err, jws.ErrSignatureInvalid)
}

func withKid(k jws.JWK, kid string) jws.JWK {
	k.Kid = kid
	return k
}

// TestAppendixCVersionMismatch: the earlier Appendix C JWS has a valid
// signature but carries pact_version 0.2, which the schema constant (0.1)
// rejects.
func TestAppendixCVersionMismatch(t *testing.T) {
	compact := strings.TrimSpace(string(readFile(t, fixturesRoot+"/parse/appendix-c-wrong-version.jws")))
	p, err := jws.Verifier{Keys: issuerResolver(t), Typ: jws.TypEvidence}.Verify(compact)
	if err != nil {
		t.Fatalf("signature must be valid: %v", err)
	}
	var ev core.Evidence
	if err := strictjson.Unmarshal(p.Payload, core.Defaults().ArtifactJSON(), &ev); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if ev.PactVersion != "0.2" {
		t.Fatalf("pact_version %q, want the 0.2 of the old fixture", ev.PactVersion)
	}
	if ev.PactVersion == core.Version {
		t.Fatal("schema constant check would accept this payload")
	}
}
