package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
)

// The codes of the draft 13.4 table that no imported package names.
const (
	codeInvalidClaim        adapter.Code = "INVALID_CLAIM"
	codeConflictingEvidence adapter.Code = "CONFLICTING_EVIDENCE"
	codeStaleEvidence       adapter.Code = "STALE_EVIDENCE"
	codeRevokedEvidence     adapter.Code = "REVOKED_EVIDENCE"
	codeSecurityHold        adapter.Code = "SECURITY_HOLD"
	codeRateLimited         adapter.Code = "RATE_LIMITED"
	codeIDConflict          adapter.Code = "ID_CONFLICT"
	codeLearningRejected    adapter.Code = "LEARNING_REJECTED"
	codeTaskLimit           adapter.Code = "TASK_LIMIT"
)

// problemOf is the draft 13.4 table: the HTTP status and a title that
// discloses nothing beyond the code (public errors avoid disclosing private
// membership, resources or issuer details).
var problemOf = map[adapter.Code]struct {
	status int
	title  string
}{
	adapter.CodeInvalidMessage:         {400, "Invalid message"},
	adapter.CodeInvalidProof:           {401, "Invalid proof"},
	contract.CodeReplay:                {409, "Replay"},
	adapter.CodeContextMismatch:        {403, "Context mismatch"},
	contract.CodeRequirementsChanged:   {409, "Requirements changed"},
	adapter.CodeUnsupportedRequirement: {422, "Unsupported requirement"},
	adapter.CodeUnsupportedPurpose:     {422, "Unsupported purpose"},
	adapter.CodeMissingField:           {403, "Missing field"},
	codeInvalidClaim:                   {403, "Invalid claim"},
	codeConflictingEvidence:            {403, "Conflicting evidence"},
	codeStaleEvidence:                  {403, "Stale evidence"},
	codeRevokedEvidence:                {403, "Revoked evidence"},
	adapter.CodeDependencyUnavailable:  {503, "Dependency unavailable"},
	codeSecurityHold:                   {403, "Security hold"},
	contract.CodeExpired:               {410, "Expired"},
	codeRateLimited:                    {429, "Rate limited"},
	codeIDConflict:                     {409, "Identifier conflict"},
	codeLearningRejected:               {409, "Learning rejected"},
	codeTaskLimit:                      {403, "Task limit"},
}

// codeOf is the draft 13.4 code an error carries. An error that carries none
// is a failure the gateway cannot classify, so it fails closed as a
// dependency that is unavailable (draft 18).
func codeOf(err error) adapter.Code {
	if c, ok := adapter.CodeOf(err); ok {
		if _, known := problemOf[c]; known {
			return c
		}
	}
	return adapter.CodeDependencyUnavailable
}

// refuse answers with the RFC 9457 problem of code (draft 13.4): type,
// title, status, code and a fresh non-sensitive request_id. ext, when not
// nil, is the problem's extensions member.
func refuse(w http.ResponseWriter, code adapter.Code, ext core.Object) {
	p, ok := problemOf[code]
	if !ok {
		code, p = adapter.CodeDependencyUnavailable, problemOf[adapter.CodeDependencyUnavailable]
	}
	body, err := json.Marshal(core.Problem{
		Type: "about:blank", Title: p.title, Status: int64(p.status), Code: string(code),
		RequestID: requestID(), Extensions: ext,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_, _ = w.Write(body)
}

// requestID is 128 random bits, base64url: it correlates a response with the
// gateway's logs and says nothing about the request.
func requestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// refusal is the code with which an enforce route refuses a request whose
// evaluation sealed with decision a.Decision (draft 11.4, 13.4), in receipt
// order:
//
//   - an evaluation past its deadline is EXPIRED (draft 12.2, 13.4);
//   - INADMISSIBLE takes the reason of the first FAIL check that does not
//     mean a stale contract, when that reason is a code of the table, and
//     otherwise INVALID_CLAIM, a required condition that fails its rule;
//   - DEFERRED is REQUIREMENTS_CHANGED when a check found the contract stale
//     (draft 11.3 step 9, 12.2: obtain a new contract), otherwise the reason
//     of the first UNKNOWN check when it is a code of the table, and
//     otherwise DEPENDENCY_UNAVAILABLE: the check cannot currently be
//     established.
func refusal(a core.AdmissionAttestation) adapter.Code {
	if a.TerminalReason == core.TerminalExpired {
		return contract.CodeExpired
	}
	known := func(reason string) bool { _, ok := problemOf[adapter.Code(reason)]; return ok }
	if a.Decision == core.DecisionInadmissible {
		for _, c := range a.Checks {
			if c.Result == core.CheckFail && !stale(c.ReasonCode) && known(c.ReasonCode) {
				return adapter.Code(c.ReasonCode)
			}
		}
		return codeInvalidClaim
	}
	for _, c := range a.Checks {
		if c.Result == core.CheckFail && stale(c.ReasonCode) {
			return contract.CodeRequirementsChanged
		}
	}
	for _, c := range a.Checks {
		if c.Result == core.CheckUnknown && known(c.ReasonCode) {
			return adapter.Code(c.ReasonCode)
		}
	}
	return adapter.CodeDependencyUnavailable
}

// stale reports the FAIL reasons that mean the contract, not the agent, is
// stale (draft 11.4).
func stale(reason string) bool {
	return reason == "SELECTION_INPUT_CHANGED" || reason == string(contract.CodeRequirementsChanged)
}
