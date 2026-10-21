package adapter

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// sentinels maps each sentinel to the draft 13.4 code the package contract
// assigns it. The literals are copied from the 13.4 table, not from the code.
var sentinels = []struct {
	name string
	err  error
	code string
}{
	{"ErrInvalidMessage", ErrInvalidMessage, "INVALID_MESSAGE"},
	{"ErrInvalidProof", ErrInvalidProof, "INVALID_PROOF"},
	{"ErrContextMismatch", ErrContextMismatch, "CONTEXT_MISMATCH"},
	{"ErrDependencyUnavailable", ErrDependencyUnavailable, "DEPENDENCY_UNAVAILABLE"},
	{"ErrUnsupportedRequirement", ErrUnsupportedRequirement, "UNSUPPORTED_REQUIREMENT"},
	{"ErrUnsupportedPurpose", ErrUnsupportedPurpose, "UNSUPPORTED_PURPOSE"},
	{"ErrMissingField", ErrMissingField, "MISSING_FIELD"},
}

func TestSentinelsMapToDraftCodes(t *testing.T) {
	for _, s := range sentinels {
		t.Run(s.name, func(t *testing.T) {
			got, ok := CodeOf(s.err)
			if !ok || string(got) != s.code {
				t.Errorf("CodeOf = %q, %v; want %q", got, ok, s.code)
			}
			wrapped := fmt.Errorf("read claim: %w", fmt.Errorf("lookup: %w", s.err))
			if got, ok := CodeOf(wrapped); !ok || string(got) != s.code {
				t.Errorf("CodeOf(wrapped) = %q, %v; want %q", got, ok, s.code)
			}
			if !errors.Is(wrapped, s.err) {
				t.Errorf("errors.Is(wrapped, %s) = false", s.name)
			}
			if s.err.Error() == "" {
				t.Errorf("%s has empty text", s.name)
			}
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	for i, a := range sentinels {
		for j, b := range sentinels {
			if (i == j) != errors.Is(a.err, b.err) {
				t.Errorf("errors.Is(%s, %s) = %v", a.name, b.name, errors.Is(a.err, b.err))
			}
		}
	}
}

func TestCodeOfIgnoresForeignErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("INVALID_PROOF"), fmt.Errorf("wrap: %w", errors.New("x"))} {
		if c, ok := CodeOf(err); ok {
			t.Errorf("CodeOf(%v) = %q, true", err, c)
		}
	}
}

// TestCodesAreInDraftTable: every Code constant is a code of the 13.4 table.
func TestCodesAreInDraftTable(t *testing.T) {
	sec := draftSection(t, "### 13.4 Errors")
	table := map[string]bool{}
	row := regexp.MustCompile("(?m)^\\| (`[A-Z_]+`(?: / `[A-Z_]+`)*) \\|")
	tok := regexp.MustCompile("`([A-Z_]+)`")
	for _, m := range row.FindAllStringSubmatch(sec, -1) {
		for _, c := range tok.FindAllStringSubmatch(m[1], -1) {
			table[c[1]] = true
		}
	}
	if len(table) < 15 {
		t.Fatalf("parsed %d codes from 13.4, want at least 15", len(table))
	}
	for _, c := range []Code{
		CodeInvalidMessage, CodeInvalidProof, CodeContextMismatch, CodeDependencyUnavailable,
		CodeUnsupportedRequirement, CodeUnsupportedPurpose, CodeMissingField,
	} {
		if !table[string(c)] {
			t.Errorf("%q is not in the draft 13.4 table", c)
		}
	}
}

func TestNativeDenialIsAnInvalidProof(t *testing.T) {
	var d error = &NativeDenial{Reason: DenialCredentialRejected}
	if !errors.Is(d, ErrInvalidProof) {
		t.Error("errors.Is(denial, ErrInvalidProof) = false")
	}
	if errors.Is(d, ErrContextMismatch) {
		t.Error("errors.Is(denial, ErrContextMismatch) = true")
	}
	if c, ok := CodeOf(fmt.Errorf("authn: %w", d)); !ok || c != CodeInvalidProof {
		t.Errorf("CodeOf(denial) = %q, %v", c, ok)
	}
	var got *NativeDenial
	if !errors.As(fmt.Errorf("authn: %w", d), &got) || got.Reason != DenialCredentialRejected {
		t.Errorf("errors.As lost the denial: %+v", got)
	}
}

// TestNativeDenialIsPointerOnly: the denial is returned as *NativeDenial so
// errors.As has one target type.
func TestNativeDenialIsPointerOnly(t *testing.T) {
	et := reflect.TypeFor[error]()
	if reflect.TypeFor[NativeDenial]().Implements(et) {
		t.Error("NativeDenial (value) implements error")
	}
	if !reflect.TypeFor[*NativeDenial]().Implements(et) {
		t.Error("*NativeDenial does not implement error")
	}
}

// TestNativeDenialDoesNotDisclose: the text of a denial depends only on the
// public reason set. Free text that an adapter puts in Reason, such as the
// name of an account, never reaches Error or PublicReason.
func TestNativeDenialDoesNotDisclose(t *testing.T) {
	leaks := []DenialReason{
		"user alice@corp.example not found",
		"password mismatch for svc-billing",
		"issuer https://idp.internal.example rejected the token",
		"",
	}
	base := (&NativeDenial{Reason: DenialCredentialRejected}).Error()
	for _, r := range leaks {
		d := &NativeDenial{Reason: r}
		if got := d.Error(); got != base {
			t.Errorf("Error() for %q = %q, want the generic %q", r, got, base)
		}
		if got := d.PublicReason(); got != DenialCredentialRejected {
			t.Errorf("PublicReason() for %q = %q, want %q", r, got, DenialCredentialRejected)
		}
		if r != "" && strings.Contains(d.Error(), string(r)) {
			t.Errorf("Error() %q contains %q", d.Error(), r)
		}
	}
	for _, r := range []DenialReason{DenialNoCredential, DenialCredentialRejected} {
		d := &NativeDenial{Reason: r}
		if d.PublicReason() != r || !strings.Contains(d.Error(), string(r)) {
			t.Errorf("valid reason %q not reported: %q", r, d.Error())
		}
	}
	if (&NativeDenial{Reason: DenialNoCredential}).Error() == base {
		t.Error("the two public reasons produce the same text")
	}
}

func TestNilNativeDenialDoesNotPanic(t *testing.T) {
	var d *NativeDenial
	if d.Error() == "" || d.PublicReason() != DenialCredentialRejected {
		t.Errorf("nil denial: %q, %q", d.Error(), d.PublicReason())
	}
}
