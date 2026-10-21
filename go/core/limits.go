package core

import (
	"errors"
	"fmt"

	"hop.top/pact-go/core/strictjson"
)

// The keys of the baseline limits that Section 20.1 of the draft names in
// GatewayMetadata.Limits. A LimitError carries one of them.
const (
	KeyMaxPresentationBytes    = "max_presentation_bytes"
	KeyMaxArtifactPayloadBytes = "max_artifact_payload_bytes"
	KeyMaxProfileBytes         = "max_profile_bytes"
	KeyMaxEvidenceArtifacts    = "max_evidence_artifacts"
	KeyMaxFieldRules           = "max_field_rules"
	KeyMaxJSONDepth            = "max_json_depth"
	KeyMaxResources            = "max_resources"
	KeyMaxDescriptionBytes     = "max_description_bytes"
)

// The baseline values of Section 20.1.
const (
	baselinePresentationBytes    = 256 << 10
	baselineArtifactPayloadBytes = 32 << 10
	baselineProfileBytes         = 32 << 10
	baselineEvidenceArtifacts    = 32
	baselineFieldRules           = 128
	baselineDepth                = 16
	baselineResources            = 256
	baselineDescriptionBytes     = 4096
)

// Reasons a limit check fails. A *LimitError wraps exactly one of them, so test
// with errors.Is.
var (
	// ErrLimitExceeded: an object is larger or has more members than a limit
	// allows.
	ErrLimitExceeded = errors.New("core: limit exceeded")
	// ErrLimitsInvalid: a Limits value is not positive or is looser than the
	// baseline.
	ErrLimitsInvalid = errors.New("core: invalid limits")
	// ErrNilObject: a Validate method was given a nil object.
	ErrNilObject = errors.New("core: nil object")
)

// LimitError names the limit that failed.
type LimitError struct {
	// Kind is ErrLimitExceeded or ErrLimitsInvalid.
	Kind error
	// Key is the Section 20.1 metadata key of the limit, such as
	// "max_json_depth".
	Key string
	// Max is what the limit allows: the configured value for ErrLimitExceeded,
	// the baseline for ErrLimitsInvalid.
	Max int
	// Got is the offending value: the measured quantity, or the configured
	// limit that is out of range.
	Got int
}

func (e *LimitError) Error() string {
	if e.Kind == ErrLimitsInvalid {
		return fmt.Sprintf("%s: %s is %d, must be 1..%d", e.Kind, e.Key, e.Got, e.Max)
	}
	return fmt.Sprintf("%s: %s is %d, at most %d", e.Kind, e.Key, e.Got, e.Max)
}

func (e *LimitError) Unwrap() error { return e.Kind }

// Limits are the resource limits a validator enforces on untrusted input
// (Section 20.1). Defaults returns the baseline. A deployment may configure
// tighter values; Check rejects a larger one, because larger limits need a
// negotiated profile and a resource-budget review.
//
// Section 20.1 also fixes lifetimes, the clock skew and the evaluation time;
// those are in package clock.
//
// The nesting depth is enforced while decoding, by strictjson. The Validate
// methods check the rest on decoded objects, and PresentationJSON,
// ArtifactJSON and ProfileJSON give the decoder the matching bounds. The byte
// limits apply to the received bytes, so a Validate method that takes a size
// wants len of the bytes that were decoded, not the length of a re-encoding.
type Limits struct {
	// PresentationBytes is the largest decoded presentation, embedded artifacts
	// included (max_presentation_bytes).
	PresentationBytes int
	// ArtifactPayloadBytes is the largest decoded payload of one signed
	// evidence or reputation artifact (max_artifact_payload_bytes).
	ArtifactPayloadBytes int
	// ProfileBytes is the largest profile JSON (max_profile_bytes).
	ProfileBytes int
	// EvidenceArtifacts is the most evidence artifacts in a presentation
	// (max_evidence_artifacts).
	EvidenceArtifacts int
	// FieldRules is the most field rules in a contract (max_field_rules).
	FieldRules int
	// Depth is the deepest JSON nesting; the outermost object or array has depth
	// 1 (max_json_depth).
	Depth int
	// Resources is the most resources in an operation (max_resources).
	Resources int
	// DescriptionBytes is the longest human-readable description in UTF-8 bytes
	// (max_description_bytes).
	DescriptionBytes int
}

// Defaults returns the baseline limits of Section 20.1.
func Defaults() Limits {
	return Limits{
		PresentationBytes:    baselinePresentationBytes,
		ArtifactPayloadBytes: baselineArtifactPayloadBytes,
		ProfileBytes:         baselineProfileBytes,
		EvidenceArtifacts:    baselineEvidenceArtifacts,
		FieldRules:           baselineFieldRules,
		Depth:                baselineDepth,
		Resources:            baselineResources,
		DescriptionBytes:     baselineDescriptionBytes,
	}
}

// Check reports whether l is a legal configuration: every limit at least 1 and
// no larger than its baseline. Equal and tighter values pass. The zero Limits
// does not, so a forgotten field is an error and not an unlimited input.
func (l Limits) Check() error {
	for _, it := range [...]struct {
		key            string
		value, ceiling int
	}{
		{KeyMaxPresentationBytes, l.PresentationBytes, baselinePresentationBytes},
		{KeyMaxArtifactPayloadBytes, l.ArtifactPayloadBytes, baselineArtifactPayloadBytes},
		{KeyMaxProfileBytes, l.ProfileBytes, baselineProfileBytes},
		{KeyMaxEvidenceArtifacts, l.EvidenceArtifacts, baselineEvidenceArtifacts},
		{KeyMaxFieldRules, l.FieldRules, baselineFieldRules},
		{KeyMaxJSONDepth, l.Depth, baselineDepth},
		{KeyMaxResources, l.Resources, baselineResources},
		{KeyMaxDescriptionBytes, l.DescriptionBytes, baselineDescriptionBytes},
	} {
		if it.value < 1 || it.value > it.ceiling {
			return &LimitError{Kind: ErrLimitsInvalid, Key: it.key, Max: it.ceiling, Got: it.value}
		}
	}
	return nil
}

func exceeds(key string, got, max int) error {
	if got > max {
		return &LimitError{Kind: ErrLimitExceeded, Key: key, Max: max, Got: got}
	}
	return nil
}

// ValidatePresentation checks a decoded presentation. size is the length in
// bytes of the decoded presentation, embedded artifacts included. It checks the
// size, the number of evidence artifacts, and, through ValidateOperation and
// ValidateIntent, the resources and the description. It returns the first limit
// exceeded.
//
// The profile inside a presentation has its own byte limit; check it with
// ValidateProfileSize on the bytes it was decoded from.
func (l Limits) ValidatePresentation(p *Presentation, size int) error {
	if p == nil {
		return fmt.Errorf("%w: presentation", ErrNilObject)
	}
	if err := exceeds(KeyMaxPresentationBytes, size, l.PresentationBytes); err != nil {
		return err
	}
	if err := exceeds(KeyMaxEvidenceArtifacts, len(p.Evidence), l.EvidenceArtifacts); err != nil {
		return err
	}
	if err := l.ValidateOperation(&p.Operation); err != nil {
		return err
	}
	return l.ValidateIntent(&p.Intent)
}

// ValidateContract checks the number of field rules in a decoded contract.
func (l Limits) ValidateContract(c *RequirementContract) error {
	if c == nil {
		return fmt.Errorf("%w: requirement contract", ErrNilObject)
	}
	return exceeds(KeyMaxFieldRules, len(c.FieldRules), l.FieldRules)
}

// ValidateOperation checks the number of resources in a decoded operation.
func (l Limits) ValidateOperation(op *OperationContext) error {
	if op == nil {
		return fmt.Errorf("%w: operation", ErrNilObject)
	}
	return exceeds(KeyMaxResources, len(op.Resources), l.Resources)
}

// ValidateIntent checks the length of a decoded intent's description in UTF-8
// bytes, which is what len reports for a Go string. strictjson has already
// rejected invalid UTF-8.
func (l Limits) ValidateIntent(in *Intent) error {
	if in == nil {
		return fmt.Errorf("%w: intent", ErrNilObject)
	}
	return exceeds(KeyMaxDescriptionBytes, len(in.Description), l.DescriptionBytes)
}

// ValidateArtifactSize checks the decoded payload size in bytes of one signed
// evidence or reputation artifact.
func (l Limits) ValidateArtifactSize(size int) error {
	return exceeds(KeyMaxArtifactPayloadBytes, size, l.ArtifactPayloadBytes)
}

// ValidateProfileSize checks the size in bytes of a profile's JSON.
func (l Limits) ValidateProfileSize(size int) error {
	return exceeds(KeyMaxProfileBytes, size, l.ProfileBytes)
}

// PresentationJSON returns the strictjson limits for decoding a presentation:
// PresentationBytes bytes and Depth levels of nesting.
func (l Limits) PresentationJSON() strictjson.Limits {
	return strictjson.Limits{MaxBytes: l.PresentationBytes, MaxDepth: l.Depth}
}

// ArtifactJSON returns the strictjson limits for decoding the payload of one
// evidence or reputation artifact: ArtifactPayloadBytes bytes and Depth levels.
func (l Limits) ArtifactJSON() strictjson.Limits {
	return strictjson.Limits{MaxBytes: l.ArtifactPayloadBytes, MaxDepth: l.Depth}
}

// ProfileJSON returns the strictjson limits for decoding a profile:
// ProfileBytes bytes and Depth levels.
func (l Limits) ProfileJSON() strictjson.Limits {
	return strictjson.Limits{MaxBytes: l.ProfileBytes, MaxDepth: l.Depth}
}
