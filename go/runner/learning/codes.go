package learning

// Transport error codes of draft Section 13.4 that a learning service
// answers with.
const (
	CodeInvalidMessage   = "INVALID_MESSAGE"
	CodeInvalidProof     = "INVALID_PROOF"
	CodeContextMismatch  = "CONTEXT_MISMATCH"
	CodeExpired          = "EXPIRED"
	CodeIDConflict       = "ID_CONFLICT"
	CodeLearningRejected = "LEARNING_REJECTED"
)

// Reason codes of draft Section 16.5 that a rejection carries.
const (
	ReasonVersionConflict            = "VERSION_CONFLICT"
	ReasonPolicyExpired              = "POLICY_EXPIRED"
	ReasonFallbackIncompatible       = "FALLBACK_INCOMPATIBLE"
	ReasonGateNotMet                 = "GATE_NOT_MET"
	ReasonSelfEvaluated              = "SELF_EVALUATED"
	ReasonObserveMode                = "OBSERVE_MODE"
	ReasonControlNotAdaptive         = "CONTROL_NOT_ADAPTIVE"
	ReasonControllerNotAuthorized    = "CONTROLLER_NOT_AUTHORIZED"
	ReasonContextNotIntended         = "CONTEXT_NOT_INTENDED"
	ReasonImplementationNotPermitted = "IMPLEMENTATION_NOT_PERMITTED"
)

// reasonOrder is the order of the Section 16.5 table, in which the reason
// codes of a rejection are listed.
var reasonOrder = []string{
	ReasonVersionConflict, ReasonPolicyExpired, ReasonFallbackIncompatible, ReasonGateNotMet,
	ReasonSelfEvaluated, ReasonObserveMode, ReasonControlNotAdaptive, ReasonControllerNotAuthorized, ReasonContextNotIntended,
	ReasonImplementationNotPermitted,
}
