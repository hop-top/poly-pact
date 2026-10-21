package adapter

import "errors"

// Code is a stable error code of the draft 13.4 table.
type Code string

// The codes this package maps its sentinel errors to.
const (
	CodeInvalidMessage         Code = "INVALID_MESSAGE"
	CodeInvalidProof           Code = "INVALID_PROOF"
	CodeContextMismatch        Code = "CONTEXT_MISMATCH"
	CodeDependencyUnavailable  Code = "DEPENDENCY_UNAVAILABLE"
	CodeUnsupportedRequirement Code = "UNSUPPORTED_REQUIREMENT"
	CodeUnsupportedPurpose     Code = "UNSUPPORTED_PURPOSE"
	CodeMissingField           Code = "MISSING_FIELD"
)

// codeError is a sentinel error that carries a draft 13.4 code. Two values are
// equal only when they are the same sentinel.
type codeError struct {
	code Code
	text string
}

func (e *codeError) Error() string { return "adapter: " + e.text }

// Code returns the draft 13.4 code of the error.
func (e *codeError) Code() Code { return e.code }

// The sentinel errors. An implementation returns them, or an error that wraps
// them with %w, so that callers match with errors.Is and read the code with
// [CodeOf].
var (
	// ErrInvalidMessage: a request or message has a form the contract does not
	// accept (INVALID_MESSAGE, HTTP 400): invalid JSON, schema or signature
	// format, or an unsupported structure. MapOperation returns it for an actual
	// request that violates a rule of the baseline HTTP mapping (draft 10.2,
	// 13.4): among them a fragment or userinfo in the target, an ambiguous
	// encoding, of which draft 10.2 gives the definition and the list, and an
	// HTTP content encoding.
	ErrInvalidMessage error = &codeError{CodeInvalidMessage, "request or message is malformed or has an unsupported structure"}

	// ErrInvalidProof: native authentication, a signature, or a holder binding
	// failed (INVALID_PROOF). [NativeDenial] is an ErrInvalidProof.
	ErrInvalidProof error = &codeError{CodeInvalidProof, "native authentication or holder binding failed"}

	// ErrContextMismatch: the principal, audience, realm, intent or actual
	// operation differs from what was bound (CONTEXT_MISMATCH).
	ErrContextMismatch error = &codeError{CodeContextMismatch, "principal, realm, intent or operation differs"}

	// ErrDependencyUnavailable: a required source cannot currently answer
	// (DEPENDENCY_UNAVAILABLE). The affected check is UNKNOWN and the admission
	// decision is DEFERRED; it is never a pass and never a failure.
	ErrDependencyUnavailable error = &codeError{CodeDependencyUnavailable, "required verification cannot currently be completed"}

	// ErrUnsupportedRequirement: a required field rule, extension, mapping or
	// context check has no installed meaning here (UNSUPPORTED_REQUIREMENT).
	// ResolveAgentBinding returns it for a workload with more than one
	// enrollment in force when the profile in use does not support workloads
	// shared by several agents (draft 17.1).
	ErrUnsupportedRequirement error = &codeError{CodeUnsupportedRequirement, "required rule, mapping or check is unsupported"}

	// ErrUnsupportedPurpose: a purpose identifier has no installed meaning
	// (UNSUPPORTED_PURPOSE).
	ErrUnsupportedPurpose error = &codeError{CodeUnsupportedPurpose, "purpose has no installed meaning"}

	// ErrMissingField: the source answers, and it holds no value at the
	// native path for the principal (MISSING_FIELD). An absent value fails
	// the rule that requires it (draft 9.2); it is not an outage. A source
	// whose record of the principal is gone, such as a deleted provisioned
	// user, answers no fact with it.
	ErrMissingField error = &codeError{CodeMissingField, "the source holds no value at the native path"}
)

// CodeOf returns the draft 13.4 code of the first error in err's chain that
// carries one, and false when none does.
func CodeOf(err error) (Code, bool) {
	var c interface{ Code() Code }
	if errors.As(err, &c) {
		return c.Code(), true
	}
	return "", false
}
