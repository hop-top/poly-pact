package ssf

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Event types. The CAEP and RISC URIs are those of CAEP 1.0 section 3 and
// RISC 1.0 section 2; the SSF control events are those of SSF 1.0 sections
// 8.1.4.1 and 8.1.5.
const (
	EventSessionRevoked                  = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange                = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceLevelChange            = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventAccountDisabled                 = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountEnabled                  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventAccountPurged                   = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventAccountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	EventCredentialCompromise            = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	// EventSessionsRevoked is the deprecated RISC event that CAEP
	// session-revoked replaces (RISC 1.0 section 2.11). The receiver maps it
	// like session-revoked because a transmitter documents sending it.
	EventSessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
	EventVerification    = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	EventStreamUpdated   = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// AccountStatePath is the one native path the receiver serves: the
// account_state fact of identity mapping and the LDAP profile (LR-20),
// extended with the values below.
const AccountStatePath = "/principal/account_state"

// The values of /principal/account_state that events produce.
const (
	StateActive                 = "active"
	StateDisabled               = "disabled"
	StateAbsent                 = "absent"
	StatePasswordChangeRequired = "password_change_required"
	StateSessionRevoked         = "session_revoked"
	StateCredentialChanged      = "credential_changed"
	StateAssuranceChanged       = "assurance_changed"
	StateCredentialCompromised  = "credential_compromised"
)

// effect is what one event does to the account state.
type effect struct {
	// state is the new account_state; empty with noEffect true when the event
	// is valid and invalidates nothing.
	state    string
	noEffect bool
}

// stateOf maps the event types that change the account state; the boolean is
// false for every other type.
var stateOf = map[string]string{
	EventSessionRevoked:                  StateSessionRevoked,
	EventSessionsRevoked:                 StateSessionRevoked,
	EventAccountDisabled:                 StateDisabled,
	EventAccountEnabled:                  StateActive,
	EventAccountPurged:                   StateAbsent,
	EventAccountCredentialChangeRequired: StatePasswordChangeRequired,
	EventCredentialCompromise:            StateCredentialCompromised,
	EventCredentialChange:                StateCredentialChanged,
	EventAssuranceLevelChange:            StateAssuranceChanged,
}

func mappedType(t string) bool { _, ok := stateOf[t]; return ok }

// interpret checks the payload of a mapped event against its definition and
// returns its effect. The payload of every event is validated before any
// event of the SET is applied.
func interpret(eventType string, payload map[string]json.RawMessage) (effect, *Error) {
	str := func(name string) (string, bool, error) {
		raw, ok := payload[name]
		if !ok {
			return "", false, nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			return "", true, fmt.Errorf("%s is not a non-empty string", name)
		}
		return s, true, nil
	}
	require := func(name string) *Error {
		if _, ok, err := str(name); err != nil {
			return reject(CodeInvalidRequest, "%s: %v", short(eventType), err)
		} else if !ok {
			return reject(CodeInvalidRequest, "%s: no %s", short(eventType), name)
		}
		return nil
	}
	e := effect{state: stateOf[eventType]}
	switch eventType {
	case EventCredentialChange:
		// CAEP 1.0 section 3.3.1: credential_type and change_type are required;
		// change_type is one of create, revoke, update, delete.
		for _, n := range []string{"credential_type", "change_type"} {
			if err := require(n); err != nil {
				return effect{}, err
			}
		}
		ct, _, _ := str("change_type")
		if !slices.Contains([]string{"create", "revoke", "update", "delete"}, ct) {
			return effect{}, reject(CodeInvalidRequest, "credential-change: change_type %q is not defined", ct)
		}
		if ct == "create" {
			return effect{noEffect: true}, nil
		}
	case EventAssuranceLevelChange:
		// CAEP 1.0 section 3.4.1: namespace and current_level are required;
		// change_direction, when present, is increase or decrease. Only an
		// increase leaves the status in force.
		for _, n := range []string{"namespace", "current_level"} {
			if err := require(n); err != nil {
				return effect{}, err
			}
		}
		d, present, err := str("change_direction")
		switch {
		case err != nil:
			return effect{}, reject(CodeInvalidRequest, "assurance-level-change: %v", err)
		case present && d != "increase" && d != "decrease":
			return effect{}, reject(CodeInvalidRequest, "assurance-level-change: change_direction %q is not defined", d)
		case d == "increase":
			return effect{noEffect: true}, nil
		}
	case EventCredentialCompromise:
		// RISC 1.0 section 2.7: credential_type is required.
		if err := require("credential_type"); err != nil {
			return effect{}, err
		}
	}
	return e, nil
}

// short names an event type in a description.
func short(t string) string {
	for i := len(t) - 1; i >= 0; i-- {
		if t[i] == '/' {
			return t[i+1:]
		}
	}
	return t
}
