package contract

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"hop.top/pact-go/core"
)

// Bounds of the RequirementContract and FieldRule schema (Appendix A.3).
const (
	maxString      = 1024
	maxFieldRules  = 128
	maxChecks      = 128
	maxIssuers     = 32
	maxExtensions  = 128
	maxCoreInteger = 1<<53 - 1
)

var (
	// randomPattern is the jti and nonce form: at least 128 bits of
	// base64url (Appendix A.2, A.3).
	randomPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	// pointerPattern is the schema pattern of path and native_path: a
	// non-empty RFC 6901 JSON Pointer.
	pointerPattern = regexp.MustCompile(`^(?:/(?:[^~/]|~[01])*)+$`)
)

// validate applies the RequirementContract schema of Appendix A.3 that
// strict decoding does not enforce, and the source-specific rules of
// Appendix A.2 and draft 9.2. It does not check the time window, the
// context or the field-rule schemas' keywords: an unsupported keyword
// makes the rule UNKNOWN, not the contract invalid (Appendix A.1).
func validate(c core.RequirementContract) error {
	switch {
	case c.PactVersion != core.Version:
		return fmt.Errorf("pact_version %q", c.PactVersion)
	case !uri(c.Issuer) || !uri(c.Subject) || !uri(c.Audience) || !uri(c.EnvironmentID):
		return errors.New("iss, sub, aud and environment_id are absolute URIs of at most 1024 characters")
	case !bounded(c.TenantID, c.ContractID, c.BaseRevision, c.SelectedSet):
		return errors.New("tenant_id, contract_id, base_revision and selected_set are 1 to 1024 characters")
	case !randomPattern.MatchString(c.JTI) || !randomPattern.MatchString(c.Nonce):
		return errors.New("jti and nonce are 22 to 128 base64url characters")
	case !integer(c.IssuedAt) || !integer(c.NotBefore) || !integer(c.Expiry):
		return errors.New("iat, nbf and exp are integers in 0..2^53-1")
	case c.IssuedAt >= c.Expiry || c.NotBefore >= c.Expiry:
		return errors.New("iat and nbf are before exp")
	case !c.Mode.Valid():
		return fmt.Errorf("mode %q", c.Mode)
	case len(c.Extensions) > maxExtensions:
		return errors.New("more than 128 extensions")
	}
	for name, d := range map[string]core.Digest{
		"holder_jkt": c.HolderJKT, "operation_digest": c.OperationDigest, "intent_digest": c.IntentDigest,
		"learning_policy_digest": c.LearningPolicyDigest, "learning_artifact_digest": c.LearningArtifactDigest,
	} {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if len(c.ContextChecks) == 0 || len(c.ContextChecks) > maxChecks || !unique(c.ContextChecks) || !bounded(c.ContextChecks...) {
		return errors.New("context_checks holds 1 to 128 distinct identifiers")
	}
	if c.FieldRules == nil || len(c.FieldRules) > maxFieldRules {
		return errors.New("field_rules is an array of at most 128 rules")
	}
	ids := make(map[string]bool, len(c.FieldRules))
	for i, r := range c.FieldRules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("field_rules[%d]: %w", i, err)
		}
		if ids[r.RuleID] {
			return fmt.Errorf("field_rules[%d]: rule_id %q is not unique", i, r.RuleID)
		}
		ids[r.RuleID] = true
	}
	return nil
}

// validateRule applies the FieldRule schema and the source rules of
// Appendix A.2.
func validateRule(r core.FieldRule) error {
	switch {
	case !bounded(r.RuleID):
		return errors.New("rule_id is 1 to 1024 characters")
	case !pointer(r.Path):
		return fmt.Errorf("path %q is not a JSON Pointer", r.Path)
	case !schemaValue(r.Schema):
		return errors.New("schema is an object or a boolean")
	case !r.Source.Valid() || !r.Comparison.Valid():
		return fmt.Errorf("source %q or comparison %q", r.Source, r.Comparison)
	case r.AllowedIssuers == nil || len(r.AllowedIssuers) > maxIssuers || !unique(r.AllowedIssuers):
		return errors.New("allowed_issuers is an array of at most 32 distinct URIs")
	case r.NativePath != nil && !pointer(*r.NativePath):
		return fmt.Errorf("native_path %q is not a JSON Pointer", *r.NativePath)
	case !integer(r.MaxAgeSeconds) || !integer(r.StatusMaxAgeSeconds):
		return errors.New("max_age_seconds and status_max_age_seconds are integers in 0..2^53-1")
	case len(r.Extensions) > maxExtensions:
		return errors.New("more than 128 extensions")
	}
	for _, iss := range r.AllowedIssuers {
		if !uri(iss) {
			return fmt.Errorf("allowed issuer %q is not an absolute URI", iss)
		}
	}
	switch r.Source {
	case core.RuleSourceSelf:
		if len(r.AllowedIssuers) != 0 || r.NativePath != nil || r.Comparison != core.ComparisonEqual ||
			r.MaxAgeSeconds != 0 || r.StatusMaxAgeSeconds != 0 {
			return errors.New("a self rule has no issuers, native_path null, comparison equal and both ages zero")
		}
		if r.Path == principalPath || within(r.Path, delegationPrefix) || within(r.Path, reputationPrefix) {
			return fmt.Errorf("a self rule cannot decide %s (draft 9.2)", r.Path)
		}
	case core.RuleSourceEvidence:
		if len(r.AllowedIssuers) == 0 || r.NativePath != nil {
			return errors.New("an evidence rule has at least one allowed issuer and native_path null")
		}
	case core.RuleSourceNative:
		if len(r.AllowedIssuers) != 0 || r.NativePath == nil {
			return errors.New("a native rule has no issuers and a native_path")
		}
	}
	return nil
}

// The profile paths a self rule can never decide (draft 9.2, Appendix
// A.2): the principal, and the delegation and reputation prefixes with
// their descendants.
const (
	principalPath    = "/attributes/environment/principal_id"
	delegationPrefix = "/attributes/delegation"
	reputationPrefix = "/attributes/reputation"
)

// within reports whether the JSON Pointer path is prefix or a descendant of
// it.
func within(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func bounded(ss ...string) bool {
	for _, s := range ss {
		if s == "" || len(s) > maxString {
			return false
		}
	}
	return true
}

// uri reports whether s is an absolute URI (the schema's format uri) of at
// most 1024 characters.
func uri(s string) bool {
	if !bounded(s) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != ""
}

func pointer(s string) bool { return len(s) <= maxString && pointerPattern.MatchString(s) }

func integer(n int64) bool { return n >= 0 && n <= maxCoreInteger }

func unique(ss []string) bool {
	seen := make(map[string]bool, len(ss))
	for _, s := range ss {
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// schemaValue reports whether raw is a JSON object or boolean.
func schemaValue(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	return raw[0] == '{' || bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false"))
}
