package validator

import (
	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
)

// The draft 13.4 codes the validator returns that package adapter has no
// constant for; package contract defines them.
const (
	codeExpired             = contract.CodeExpired
	codeReplay              = contract.CodeReplay
	codeRequirementsChanged = contract.CodeRequirementsChanged
	codeSecurityHold        = contract.CodeSecurityHold
)

// rejection is the error of a request rejected before an authenticated
// evaluation (draft 12.2): it carries its draft 13.4 code, which
// adapter.CodeOf reads.
type rejection struct {
	code adapter.Code
	text string
}

func (r *rejection) Error() string { return "validator: " + string(r.code) + ": " + r.text }

// Code returns the draft 13.4 code.
func (r *rejection) Code() adapter.Code { return r.code }

func reject(code adapter.Code, text string) error {
	if code == "" {
		code = adapter.CodeInvalidMessage
	}
	return &rejection{code: code, text: text}
}

// statuses is the HTTP status of each code of the draft 13.4 table.
var statuses = map[adapter.Code]int64{
	adapter.CodeInvalidMessage:         400,
	adapter.CodeInvalidProof:           401,
	codeReplay:                         409,
	adapter.CodeContextMismatch:        403,
	codeRequirementsChanged:            409,
	adapter.CodeUnsupportedRequirement: 422,
	adapter.CodeUnsupportedPurpose:     422,
	adapter.CodeMissingField:           403,
	adapter.CodeDependencyUnavailable:  503,
	codeExpired:                        410,
	codeSecurityHold:                   403,
}

// titles are the non-disclosing titles of the codes (draft 13.4: public
// errors avoid disclosing private membership or issuer details).
var titles = map[adapter.Code]string{
	adapter.CodeInvalidMessage:         "Invalid message",
	adapter.CodeInvalidProof:           "Invalid proof",
	codeReplay:                         "Replay",
	adapter.CodeContextMismatch:        "Context mismatch",
	codeRequirementsChanged:            "Requirements changed",
	adapter.CodeUnsupportedRequirement: "Unsupported requirement",
	adapter.CodeUnsupportedPurpose:     "Unsupported purpose",
	adapter.CodeMissingField:           "Missing field",
	adapter.CodeDependencyUnavailable:  "Dependency unavailable",
	codeExpired:                        "Expired",
	codeSecurityHold:                   "Security hold",
}

// ProblemOf returns the RFC 9457 problem details of the transport error err
// carries (draft 13.4), with the non-sensitive requestID, and false when err
// carries no code of the draft 13.4 table. The detail of err is not copied:
// a public error discloses only its code.
func ProblemOf(err error, requestID string) (core.Problem, bool) {
	code, ok := adapter.CodeOf(err)
	if !ok || err == nil {
		return core.Problem{}, false
	}
	status, ok := statuses[code]
	if !ok {
		return core.Problem{}, false
	}
	return core.Problem{Type: "about:blank", Title: titles[code], Status: status, Code: string(code), RequestID: requestID}, true
}
