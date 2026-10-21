package ssf

import (
	"errors"
	"fmt"
)

// The Security Event Token error codes of RFC 8935 section 2.4, which a
// push receiver returns with HTTP 400 (section 2.3) and a poll receiver
// returns in setErrs (RFC 8936 section 2.4).
const (
	// CodeInvalidRequest: the body is not a SET, or an event payload does not
	// conform to its event's definition.
	CodeInvalidRequest = "invalid_request"
	// CodeInvalidKey: the key that signed the SET is unknown or unacceptable,
	// or the signature does not verify.
	CodeInvalidKey = "invalid_key"
	// CodeInvalidIssuer: the SET issuer is not one this receiver is configured
	// for.
	CodeInvalidIssuer = "invalid_issuer"
	// CodeInvalidAudience: the SET audience does not name this receiver.
	CodeInvalidAudience = "invalid_audience"
	// CodeAuthenticationFailed: the transmitter did not authenticate.
	CodeAuthenticationFailed = "authentication_failed"
	// CodeAccessDenied is the code for a transmitter that is not authorized
	// to transmit the SET to this receiver. The receiver reports it for no
	// condition today, since a SET the receiver is free to ignore (RFC 8935
	// section 3) is acknowledged, not refused.
	CodeAccessDenied = "access_denied"
)

// Error is a SET the receiver rejects: the SET is not applied, and the
// transmitter is told why. Any other error that Accept returns is a failure
// of the receiver or one of its dependencies, after which the same SET is
// accepted on a retry.
type Error struct {
	// Code is one of the Code constants.
	Code string
	// Description is a human-readable diagnostic. It never carries a subject
	// identifier.
	Description string
}

func (e *Error) Error() string { return "ssf: " + e.Code + ": " + e.Description }

func reject(code, format string, args ...any) *Error {
	return &Error{Code: code, Description: fmt.Sprintf(format, args...)}
}

// ErrUnknownKey: a key source holds no usable key with the requested kid.
// The receiver reports it as [CodeInvalidKey].
var ErrUnknownKey = errors.New("ssf: no such key")
