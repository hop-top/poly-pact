package learning

import (
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"hop.top/pact-go/core"
	score "hop.top/pact-go/reputation"
)

// The checks below are the shape rules of the JSON Schema of draft Appendix
// A.3 that decide a learning message's validity and that strict decoding
// does not enforce: required array minimums, enum sets, digest patterns and
// the cross-object rules of Appendix A.2. A message that fails one is
// INVALID_MESSAGE (draft Section 13.4).

func validJTI(s string) bool {
	if len(s) < 22 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !isBase64URL(c) {
			return false
		}
	}
	return true
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// nonEmpty checks a string member against the 1 to 1024 bound of the
// schema (Appendix A.3), in characters, as JSON Schema maxLength counts
// them, not bytes.
func nonEmpty(name, s string) error {
	if n := utf8.RuneCountInString(s); n < 1 || n > 1024 {
		return fmt.Errorf("%s must be 1 to 1024 characters", name)
	}
	return nil
}

func nonEmptyAll(pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if err := nonEmpty(pairs[i], pairs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func claimsOK(version, jti string, iat, nbf, exp int64) error {
	switch {
	case version != core.Version:
		return fmt.Errorf("pact_version %q, want %q", version, core.Version)
	case !validJTI(jti):
		return errors.New("jti must be 22 to 128 base64url characters")
	case iat < 0 || nbf < 0 || exp < 0:
		return errors.New("iat, nbf and exp are not negative")
	case iat >= exp || nbf >= exp:
		return errors.New("iat and nbf are before exp (Appendix A.2)")
	}
	return nil
}

func uniqueStrings(name string, s []string, min, max int) error {
	if len(s) < min || len(s) > max {
		return fmt.Errorf("%s has %d items, want %d to %d", name, len(s), min, max)
	}
	seen := map[string]bool{}
	for _, v := range s {
		if err := nonEmpty(name+" item", v); err != nil {
			return err
		}
		if seen[v] {
			return fmt.Errorf("%s repeats %q", name, v)
		}
		seen[v] = true
	}
	return nil
}

func contextOK(c core.ReputationContext) error {
	return nonEmptyAll("tenant_id", c.TenantID, "environment_id", c.EnvironmentID, "agent_id", c.AgentID,
		"purpose_id", c.PurposeID, "action_class", c.ActionClass, "resource_class", c.ResourceClass, "runtime_class", c.RuntimeClass)
}

func contextsOK(name string, cs []core.ReputationContext) error {
	if len(cs) < 1 || len(cs) > 128 {
		return fmt.Errorf("%s has %d contexts, want 1 to 128", name, len(cs))
	}
	for i, c := range cs {
		if err := contextOK(c); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, i, err)
		}
	}
	return nil
}

// ValidatePolicy applies the LearningPolicy schema of Appendix A.3. A policy
// without a release gate of Appendix A.2 (minimum independent tasks,
// observation and shadow durations, immutable test-suite digests, metric
// bounds) fails it.
func ValidatePolicy(p core.LearningPolicy) error {
	if err := claimsOK(p.PactVersion, p.JTI, p.IssuedAt, p.NotBefore, p.Expiry); err != nil {
		return err
	}
	if err := nonEmptyAll("iss", p.Issuer, "sub", p.Subject, "aud", p.Audience, "tenant_id", p.TenantID, "policy_id", p.PolicyID,
		"environment_id", p.EnvironmentID, "base_revision", p.BaseRevision, "conservative_set", p.ConservativeSet); err != nil {
		return err
	}
	if !p.Mode.Valid() {
		return fmt.Errorf("mode %q is not observe or bounded_autonomous", p.Mode)
	}
	for _, c := range []struct {
		name string
		s    []string
		max  int
	}{
		{"controller_ids", p.ControllerIDs, 32}, {"allowed_requirement_sets", p.AllowedRequirementSets, 64},
		{"permitted_implementation_ids", p.PermittedImplementationIDs, 32}, {"hold_clearance_authorities", p.HoldClearanceAuthorities, 32},
		{"evaluation_policy.required_evaluator_ids", p.EvaluationPolicy.RequiredEvaluatorIDs, 32},
		{"evaluation_policy.rollback_condition_ids", p.EvaluationPolicy.RollbackConditionIDs, 64},
	} {
		if err := uniqueStrings(c.name, c.s, 1, c.max); err != nil {
			return err
		}
	}
	if n := len(p.PermittedArtifactTypes); n < 1 || n > 5 {
		return fmt.Errorf("permitted_artifact_types has %d items, want 1 to 5", n)
	}
	for _, t := range p.PermittedArtifactTypes {
		if !t.Valid() {
			return fmt.Errorf("permitted_artifact_types: %q is not an artifact type", t)
		}
	}
	for i, f := range p.AdaptiveFields {
		if err := nonEmpty(fmt.Sprintf("adaptive_fields[%d].control_id", i), f.ControlID); err != nil {
			return err
		}
	}
	return evaluationPolicyOK(p.EvaluationPolicy, p.DataPolicy)
}

func evaluationPolicyOK(e core.EvaluationPolicy, d core.DataPolicy) error {
	if e.MinimumIndependentTasks < 1 || e.MinimumObservationSeconds < 1 || e.MinimumShadowSeconds < 1 {
		return errors.New("evaluation_policy: minimum_independent_tasks, minimum_observation_seconds and minimum_shadow_seconds are at least 1")
	}
	if err := nonEmpty("evaluation_policy.holdout_policy_id", e.HoldoutPolicyID); err != nil {
		return err
	}
	if n := len(e.ImmutableTestSuiteDigests); n < 1 || n > 32 {
		return fmt.Errorf("evaluation_policy.immutable_test_suite_digests has %d items, want 1 to 32: a release gate is required (Appendix A.2)", n)
	}
	seen := map[core.Digest]bool{}
	for _, dg := range e.ImmutableTestSuiteDigests {
		if err := dg.Validate(); err != nil {
			return fmt.Errorf("evaluation_policy.immutable_test_suite_digests: %w", err)
		}
		if seen[dg] {
			return errors.New("evaluation_policy.immutable_test_suite_digests repeats a digest")
		}
		seen[dg] = true
	}
	if n := len(e.MetricBounds); n < 1 || n > 64 {
		return fmt.Errorf("evaluation_policy.metric_bounds has %d metrics, want 1 to 64", n)
	}
	for k, b := range e.MetricBounds {
		if !b.Direction.Valid() {
			return fmt.Errorf("evaluation_policy.metric_bounds[%s]: direction %q", k, b.Direction)
		}
	}
	if e.MaximumRolloutPercent < 1 || e.MaximumRolloutPercent > 100 {
		return errors.New("evaluation_policy.maximum_rollout_percent is 1 to 100")
	}
	if err := score.CheckDataPolicy(d); err != nil {
		return fmt.Errorf("data_policy: %w", err)
	}
	return nil
}

// ValidateArtifact applies the LearningArtifact schema of Appendix A.3 and
// the rule that an artifact's sub is its artifact URI (Appendix A.2).
func ValidateArtifact(a core.LearningArtifact) error {
	if err := claimsOK(a.PactVersion, a.JTI, a.IssuedAt, a.NotBefore, a.Expiry); err != nil {
		return err
	}
	if err := nonEmptyAll("iss", a.Issuer, "sub", a.Subject, "aud", a.Audience, "tenant_id", a.TenantID, "artifact_id", a.ArtifactID,
		"version", a.Version, "implementation_id", a.ImplementationID, "base_revision", a.BaseRevision, "artifact_store_ref", a.ArtifactStoreRef); err != nil {
		return err
	}
	if !a.ModelType.Valid() {
		return fmt.Errorf("model_type %q is not an artifact type", a.ModelType)
	}
	for name, d := range map[string]core.Digest{"content_digest": a.ContentDigest, "source_data_manifest_digest": a.SourceDataManifestDigest,
		"feature_schema_digest": a.FeatureSchemaDigest, "training_configuration_digest": a.TrainingConfigurationDigest,
		"evaluation_report_digest": a.EvaluationReportDigest} {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if a.ParentArtifactDigest != nil {
		if err := a.ParentArtifactDigest.Validate(); err != nil {
			return fmt.Errorf("parent_artifact_digest: %w", err)
		}
	}
	if err := contextsOK("intended_contexts", a.IntendedContexts); err != nil {
		return err
	}
	if a.OutputControls == nil {
		return errors.New("output_controls is required")
	}
	if err := uniqueStrings("output_controls", a.OutputControls, 0, 64); err != nil {
		return err
	}
	if a.Subject != a.ArtifactID {
		return fmt.Errorf("sub %q is not the artifact_id %q (Appendix A.2)", a.Subject, a.ArtifactID)
	}
	return nil
}

// ValidateEvent applies the LearningEvent schema of Appendix A.3 and the
// event rules of Appendix A.2: expected_state and transition are a row of
// the Section 16.5 table; activate_artifact_digest names the artifact for
// ACTIVE, the fallback or null for ROLLED_BACK and is null otherwise; a
// rollback to null records FALLBACK_INCOMPATIBLE; and an ACTIVE event's
// expected_active_digest is null, since a promotion replaces only the
// conservative set.
func ValidateEvent(e core.LearningEvent) error {
	if err := claimsOK(e.PactVersion, e.JTI, e.IssuedAt, e.NotBefore, e.Expiry); err != nil {
		return err
	}
	if err := nonEmptyAll("iss", e.Issuer, "sub", e.Subject, "aud", e.Audience, "tenant_id", e.TenantID, "event_id", e.EventID,
		"environment_id", e.EnvironmentID); err != nil {
		return err
	}
	if err := e.ArtifactDigest.Validate(); err != nil {
		return fmt.Errorf("artifact_digest: %w", err)
	}
	if err := e.PolicyDigest.Validate(); err != nil {
		return fmt.Errorf("policy_digest: %w", err)
	}
	for name, d := range map[string]*core.Digest{"previous_artifact_digest": e.PreviousArtifactDigest,
		"expected_active_digest": e.ExpectedActiveDigest, "activate_artifact_digest": e.ActivateArtifactDigest} {
		if d != nil {
			if err := d.Validate(); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if !e.Transition.Valid() {
		return fmt.Errorf("transition %q", e.Transition)
	}
	if !e.ExpectedState.Valid() {
		return fmt.Errorf("expected_state %q", e.ExpectedState)
	}
	if e.EffectiveAt < 0 {
		return errors.New("effective_at is not negative")
	}
	if err := contextsOK("scope_contexts", e.ScopeContexts); err != nil {
		return err
	}
	if e.EvaluationRefs == nil {
		return errors.New("evaluation_refs is required")
	}
	if err := uniqueStrings("evaluation_refs", e.EvaluationRefs, 0, 64); err != nil {
		return err
	}
	if err := uniqueStrings("reason_codes", e.ReasonCodes, 1, 32); err != nil {
		return err
	}
	if !slices.Contains(transitions[e.ExpectedState], e.Transition) {
		return fmt.Errorf("%s to %s is not a row of the Section 16.5 table (Appendix A.2)", e.ExpectedState, e.Transition)
	}
	switch e.Transition {
	case core.TransitionActive:
		if e.ActivateArtifactDigest == nil || *e.ActivateArtifactDigest != e.ArtifactDigest {
			return errors.New("an ACTIVE event names the artifact in activate_artifact_digest (Appendix A.2)")
		}
		if e.ExpectedActiveDigest != nil {
			return errors.New("an ACTIVE event has a null expected_active_digest: a promotion replaces only the conservative set (Section 16.5, Appendix A.2)")
		}
	case core.TransitionRolledBack:
		if e.ActivateArtifactDigest == nil && !slices.Contains(e.ReasonCodes, ReasonFallbackIncompatible) {
			return errors.New("a rollback to null names FALLBACK_INCOMPATIBLE in reason_codes (Appendix A.2)")
		}
	default:
		if e.ActivateArtifactDigest != nil {
			return fmt.Errorf("a %s event has a null activate_artifact_digest (Appendix A.2)", e.Transition)
		}
	}
	if !sameDigest(e.PreviousArtifactDigest, e.ExpectedActiveDigest) {
		return errors.New("previous_artifact_digest equals expected_active_digest, the expected previous artifact of the compare-and-swap (Section 16.5, Appendix A.2)")
	}
	return nil
}

// ValidateReport applies the OutcomeReport schema of Appendix A.3 and the
// CORRECTION rule of Appendix A.2.
func ValidateReport(r core.OutcomeReport) error {
	if err := claimsOK(r.PactVersion, r.JTI, r.IssuedAt, r.NotBefore, r.Expiry); err != nil {
		return err
	}
	if err := nonEmptyAll("iss", r.Issuer, "sub", r.Subject, "aud", r.Audience, "tenant_id", r.TenantID, "event_id", r.EventID,
		"environment_id", r.EnvironmentID, "task_id", r.TaskID, "operation_id", r.OperationID); err != nil {
		return err
	}
	if !r.ReporterRole.Valid() || !r.EventKind.Valid() || !r.Result.Valid() || !r.Dimension.Valid() || !r.Severity.Valid() {
		return errors.New("reporter_role, event_kind, result, dimension or severity is not a defined value")
	}
	if err := contextOK(r.Context); err != nil {
		return fmt.Errorf("context: %w", err)
	}
	if r.ObservedAt < 0 {
		return errors.New("observed_at is not negative")
	}
	if r.EvidenceRefs == nil || r.Supersedes == nil {
		return errors.New("evidence_refs and supersedes are required")
	}
	if err := uniqueStrings("evidence_refs", r.EvidenceRefs, 0, 64); err != nil {
		return err
	}
	if err := uniqueStrings("supersedes", r.Supersedes, 0, 64); err != nil {
		return err
	}
	if (r.EventKind == core.EventCorrection) != (len(r.Supersedes) > 0) {
		return errors.New("CORRECTION requires a nonempty supersedes, and no other event kind has one (Appendix A.2)")
	}
	return nil
}
