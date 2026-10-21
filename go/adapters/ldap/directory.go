package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"hop.top/pact-go/internal/ascii"
)

// Directory opens sessions to the directory server of one realm. [Server] is
// the implementation on github.com/go-ldap/ldap/v3; a test supplies its own.
type Directory interface {
	// Open returns a new session over a protected connection: LDAPS, or LDAP
	// after a StartTLS that returned success, with the server identity
	// checked against the configured trust anchors (profile LR-4). An error
	// means no such session exists, and nothing was sent on it.
	Open(ctx context.Context) (Session, error)
}

// Session is one connection to a directory server. The adapter uses a session
// for one purpose only: a lookup session carries the lookup account's bind and
// its searches, a user session carries one user bind and the checks after it
// (profile LR-7).
type Session interface {
	// Bind sends a version 3 simple bind with the name dn and the password
	// (RFC 4511, section 4.2). The adapter never calls it with an empty
	// password. A result other than success is a *[ResultError]; any other
	// error means the bind could not be completed.
	Bind(ctx context.Context, dn, password string) error
	// Search sends q and returns the entries, the search result references
	// and the result code of the search, whatever the code. An error means
	// the search could not be completed.
	Search(ctx context.Context, q Query) (Result, error)
	// WhoAmI sends the "Who am I?" operation (RFC 4532). present is false
	// when the response has no response field; a result other than success
	// is a *[ResultError].
	WhoAmI(ctx context.Context) (authzID string, present bool, err error)
	// Close closes the connection.
	Close() error
}

// ResultCode is an LDAP result code (RFC 4511, section 4.1.9 and Appendix A).
type ResultCode int

// The result codes the adapter tells apart (RFC 4511, section 4.1.9).
const (
	ResultSuccess                     ResultCode = 0
	ResultOperationsError             ResultCode = 1
	ResultProtocolError               ResultCode = 2
	ResultTimeLimitExceeded           ResultCode = 3
	ResultSizeLimitExceeded           ResultCode = 4
	ResultAuthMethodNotSupported      ResultCode = 7
	ResultStrongerAuthRequired        ResultCode = 8
	ResultReferral                    ResultCode = 10
	ResultAdminLimitExceeded          ResultCode = 11
	ResultConfidentialityRequired     ResultCode = 13
	ResultNoSuchObject                ResultCode = 32
	ResultInvalidDNSyntax             ResultCode = 34
	ResultInappropriateAuthentication ResultCode = 48
	ResultInvalidCredentials          ResultCode = 49
	ResultInsufficientAccessRights    ResultCode = 50
	ResultBusy                        ResultCode = 51
	ResultUnavailable                 ResultCode = 52
	ResultUnwillingToPerform          ResultCode = 53
	ResultOther                       ResultCode = 80
)

// ResultError is a result code other than success.
type ResultError struct {
	Code ResultCode
}

func (e *ResultError) Error() string { return fmt.Sprintf("ldap: result code %d", int(e.Code)) }

// Scope is the scope of a search (RFC 4511, section 4.5.1.2).
type Scope int

// The scopes the adapter uses.
const (
	ScopeBase    Scope = 0
	ScopeSubtree Scope = 2
)

// Query is a search request (RFC 4511, section 4.5.1). Aliases are never
// dereferenced and the request asks for values, not types only.
type Query struct {
	Base       string
	Scope      Scope
	Filter     Filter
	Attributes []string
	// SizeLimit is the largest number of entries to return; 0 is no limit.
	SizeLimit int
	// TimeLimit is the time the server may spend on the search, in whole
	// seconds; 0 is no limit.
	TimeLimit time.Duration
}

// Result is the answer to a search.
type Result struct {
	Entries []Entry
	// References are the URIs of the search result references.
	References []string
	// Code is the result code of the search result done message.
	Code ResultCode
}

// Entry is one search result entry.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// Attribute is one attribute of an entry, with its values as octets.
type Attribute struct {
	Name   string
	Values [][]byte
}

// Values returns the values of the attribute name, compared
// case-insensitively, as attribute descriptions are (RFC 4512, section 2.5).
func (e Entry) Values(name string) [][]byte {
	for _, a := range e.Attributes {
		if ascii.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

// Filter is a search filter. Its String method is the string representation
// of RFC 4515.
type Filter interface {
	String() string
	isFilter()
}

// And is the and filter of its items; it must have at least one (RFC 4511,
// section 4.5.1.7).
type And []Filter

// Equal is an equality match of Attr with the octets of Value. A Binary value,
// such as an objectGUID, is written with every octet escaped.
type Equal struct {
	Attr   string
	Value  []byte
	Binary bool
}

// Present is a presence filter of Attr.
type Present struct {
	Attr string
}

// InChainOID is the matching rule LDAP_MATCHING_RULE_IN_CHAIN of Active
// Directory, which walks the chain of ancestry of DN-valued attributes
// (Microsoft Learn, Search Filter Syntax).
const InChainOID = "1.2.840.113556.1.4.1941"

// InChain is the extensible match (Attr:1.2.840.113556.1.4.1941:=DN).
type InChain struct {
	Attr string
	DN   string
}

func (And) isFilter()     {}
func (Equal) isFilter()   {}
func (Present) isFilter() {}
func (InChain) isFilter() {}

func (f And) String() string {
	var b strings.Builder
	b.WriteString("(&")
	for _, x := range f {
		b.WriteString(x.String())
	}
	b.WriteString(")")
	return b.String()
}

func (f Equal) String() string {
	if f.Binary {
		return "(" + f.Attr + "=" + escapeOctets(f.Value) + ")"
	}
	return "(" + f.Attr + "=" + EscapeValue(f.Value) + ")"
}

// escapeOctets writes every octet of v as a backslash and two hexadecimal
// digits, the form Microsoft Learn's Search Filter Syntax gives for
// arbitrary binary data.
func escapeOctets(v []byte) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 3*len(v))
	for _, c := range v {
		b = append(b, '\\', hex[c>>4], hex[c&0xf])
	}
	return string(b)
}

func (f Present) String() string { return "(" + f.Attr + "=*)" }

func (f InChain) String() string {
	return "(" + f.Attr + ":" + InChainOID + ":=" + EscapeValue([]byte(f.DN)) + ")"
}

// EscapeValue writes v as an assertion value of RFC 4515, section 3: the
// octets of "*", "(", ")", "\" and NUL, every other control octet, and every
// octet above 0x7E are written as a backslash and two hexadecimal digits, so
// that no value can change the structure of a filter. A binary value such as
// an objectGUID is written octet by octet the same way.
func EscapeValue(v []byte) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	for _, c := range v {
		switch {
		case c == '*' || c == '(' || c == ')' || c == '\\' || c < 0x21 && c != ' ' || c > 0x7e:
			b.WriteByte('\\')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
