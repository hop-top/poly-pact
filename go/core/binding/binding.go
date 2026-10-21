package binding

import (
	"errors"
	"fmt"
	"net/http"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
)

// The errors of this package. Test with errors.Is.
var (
	// ErrInvalidConfig: the Config is unusable. It is a gateway
	// misconfiguration, not a fault of the request.
	ErrInvalidConfig = errors.New("binding: invalid configuration")

	// ErrInvalidRequest: the request has a form the baseline HTTP mapping
	// refuses. Every such error is a *RequestError that names the rule.
	ErrInvalidRequest = errors.New("binding: request refused by the baseline HTTP mapping")

	// ErrBodyRead: the request body could not be read to its end, for a reason
	// other than its size. The underlying error is wrapped too.
	ErrBodyRead = errors.New("binding: request body could not be read")
)

// Rule names the rule of the baseline HTTP mapping that a request broke.
type Rule string

// The rules. The package documentation gives the source of each.
const (
	RuleNoRequest          Rule = "no-request"
	RuleMethod             Rule = "method"
	RuleTargetForm         Rule = "target-form"
	RuleFragment           Rule = "fragment"
	RuleUserinfo           Rule = "userinfo"
	RuleNonASCIIHost       Rule = "non-ascii-host"
	RuleInvalidCharacter   Rule = "invalid-character"
	RuleMalformedEscape    Rule = "malformed-escape"
	RuleEncodedUnreserved  Rule = "encoded-unreserved"
	RuleLowercaseHex       Rule = "lowercase-hex"
	RuleInvalidUTF8        Rule = "invalid-utf8"
	RuleEncodedSlash       Rule = "encoded-slash"
	RuleDotSegment         Rule = "dot-segment"
	RuleTargetTooLong      Rule = "target-too-long"
	RuleContentEncoding    Rule = "content-encoding"
	RuleTransferCoding     Rule = "transfer-coding"
	RuleBodyTooLarge       Rule = "body-too-large"
	RuleHeaderValue        Rule = "header-value"
	RuleHeaderTooLong      Rule = "header-too-long"
	RuleHeaderKeyCollision Rule = "header-key-collision"
	RuleDuplicateHost      Rule = "duplicate-host"
	RuleMissingHost        Rule = "missing-host"
	RuleInvalidHost        Rule = "invalid-host"
)

// RequestError is a request refused under one rule. It wraps
// [ErrInvalidRequest].
type RequestError struct {
	Rule Rule
	// Detail says where the rule was broken. It quotes little or none of the
	// request.
	Detail string
}

func (e *RequestError) Error() string {
	return "binding: request refused (" + string(e.Rule) + "): " + e.Detail
}

func (e *RequestError) Unwrap() error { return ErrInvalidRequest }

func refuse(rule Rule, format string, args ...any) error {
	return &RequestError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// FromRequest derives the operation context of the baseline HTTP mapping
// (draft 10.2) from r, a request as a net/http server received it.
//
// The principal, action and resources are the caller's: it derives them from
// the authenticated request and its installed mapping rules, never from a
// list the client supplied. FromRequest copies them as given. It leaves
// OperationID and EnvironmentID empty for the caller to set, and does not
// check the 20.1 limits; [core.Limits.ValidateOperation] does.
//
// Once the body has been read, r.Body is an in-memory copy of it and
// r.GetBody returns that copy too. When the body is too large, r.Body still
// yields every byte of the original body.
//
// The error wraps [ErrInvalidConfig], [ErrInvalidRequest] (a *RequestError)
// or [ErrBodyRead].
func FromRequest(cfg Config, r *http.Request, principalID, action string, resources []string) (core.OperationContext, error) {
	origin, allow, err := cfg.prepare()
	if err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, refuse(RuleNoRequest, "no request or no URL")
	}
	method, err := uppercaseMethod(r.Method)
	if err != nil {
		return core.OperationContext{}, err
	}
	pathQuery, err := requestTarget(r)
	if err != nil {
		return core.OperationContext{}, err
	}
	target := origin + pathQuery
	if len(target) > maxTargetURI {
		return core.OperationContext{}, refuse(RuleTargetTooLong, "target_uri has %d characters, at most %d", len(target), maxTargetURI)
	}
	if err := checkHost(r); err != nil {
		return core.OperationContext{}, err
	}
	if err := checkCodings(r); err != nil {
		return core.OperationContext{}, err
	}
	body, err := readBody(r, cfg.MaxBody)
	if err != nil {
		return core.OperationContext{}, err
	}
	headers, err := selectHeaders(r.Header, allow, len(body) > 0)
	if err != nil {
		return core.OperationContext{}, err
	}
	return core.OperationContext{
		PrincipalID: principalID,
		Action:      action,
		Resources:   append([]string{}, resources...),
		Method:      method,
		TargetURI:   target,
		BodyDigest:  digest.BytesDigest(body),
		Headers:     headers,
	}, nil
}

// uppercaseMethod returns the method in uppercase. Only ASCII letters are
// accepted, matching the schema pattern ^[A-Z]+$ for method, so no Unicode
// case mapping can turn another character into a letter.
func uppercaseMethod(m string) (string, error) {
	if m == "" {
		return "", refuse(RuleMethod, "empty method")
	}
	for i := 0; i < len(m); i++ {
		if !isAlpha(m[i]) {
			return "", refuse(RuleMethod, "method has a byte other than an ASCII letter at offset %d", i)
		}
	}
	b := []byte(m)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b), nil
}
