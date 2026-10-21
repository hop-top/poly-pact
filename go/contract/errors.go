package contract

import "hop.top/pact-go/adapter"

// The codes of the draft 13.4 table that this package returns and that
// [adapter] has no constant for.
const (
	CodeReplay              adapter.Code = "REPLAY"
	CodeRequirementsChanged adapter.Code = "REQUIREMENTS_CHANGED"
	CodeExpired             adapter.Code = "EXPIRED"
	CodeSecurityHold        adapter.Code = "SECURITY_HOLD"
)

// codeError is a sentinel error that carries a draft 13.4 code.
type codeError struct {
	code adapter.Code
	text string
}

func (e *codeError) Error() string { return "contract: " + e.text }

// Code returns the draft 13.4 code of the error, so that [adapter.CodeOf]
// reads it.
func (e *codeError) Code() adapter.Code { return e.code }

// The sentinel errors. Every error of the package wraps exactly one.
var (
	// ErrInvalidMessage: a contract that is not a valid RequirementContract
	// (schema, Appendix A.2, lifetime longer than 60 s, iat or nbf after now
	// plus skew), a JWS of another typ or of a malformed form, or
	// requirements a publisher cannot issue (INVALID_MESSAGE).
	ErrInvalidMessage error = &codeError{adapter.CodeInvalidMessage, "malformed or invalid requirement contract"}

	// ErrInvalidProof: the publisher's signature does not verify under the
	// keys of the trust record iss names, or there is no native
	// authentication, no binding of the named agent to the authenticated
	// workload, or a revoked binding or one of another key to issue a
	// contract for (INVALID_PROOF, draft 9.1).
	ErrInvalidProof error = &codeError{adapter.CodeInvalidProof, "publisher signature, native authentication or agent/key binding failed"}

	// ErrSecurityHold: the agent binding a contract request names is marked
	// compromised (SECURITY_HOLD, draft 6.4, 9.1).
	ErrSecurityHold error = &codeError{CodeSecurityHold, "agent binding is marked compromised"}

	// ErrUnsupportedPurpose: the purpose a contract request's intent names
	// has no installed meaning (UNSUPPORTED_PURPOSE, draft 10.1).
	ErrUnsupportedPurpose error = &codeError{adapter.CodeUnsupportedPurpose, "purpose has no installed meaning"}

	// ErrContextMismatch: the subject, audience or realm differs from the one
	// expected, or a nonce record differs from the registered one
	// (CONTEXT_MISMATCH).
	ErrContextMismatch error = &codeError{adapter.CodeContextMismatch, "subject, audience, realm or bound context differs"}

	// ErrUnsupportedRequirement: the contract carries an extension the
	// verifier does not support (UNSUPPORTED_REQUIREMENT, draft 7.1).
	ErrUnsupportedRequirement error = &codeError{adapter.CodeUnsupportedRequirement, "unsupported extension"}

	// ErrRequirementsChanged: the contract pins a base revision or learning
	// version that is no longer active (REQUIREMENTS_CHANGED, draft 9.4,
	// 12.2).
	ErrRequirementsChanged error = &codeError{CodeRequirementsChanged, "contract is no longer active"}

	// ErrExpired: now is at or after the contract's exp (EXPIRED, draft 7.5,
	// 12.2). There is no grace period.
	ErrExpired error = &codeError{CodeExpired, "contract expired"}

	// ErrReplay: the nonce was already consumed, or was never registered
	// (REPLAY, draft 7.5).
	ErrReplay error = &codeError{CodeReplay, "nonce already consumed or not issued"}

	// ErrDependencyUnavailable: the replay store is full or unavailable, or
	// the signer failed (DEPENDENCY_UNAVAILABLE). It defers; it never admits
	// (draft 7.5).
	ErrDependencyUnavailable error = &codeError{adapter.CodeDependencyUnavailable, "replay store or signer unavailable"}
)
