//! The wire objects of reputation, outcomes, learning and gateway metadata
//! (draft Appendix A.3). The conventions are those of [`crate::core::types`].

use std::collections::BTreeMap;

use super::enums::*;
use super::types::{present, wire};
use super::{Digest, Object};

wire!(
    /// The context a reputation value or an outcome applies to.
    ReputationContext {
        tenant_id: String,
        environment_id: String,
        agent_id: String,
        purpose_id: String,
        action_class: String,
        resource_class: String,
        runtime_class: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The statistics of one reputation dimension, in basis points.
    DimensionStats {
        score_bps: i64,
        confidence_bps: i64,
        independent_tasks: i64,
        qualified_events: i64,
        newest_event_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The `dimensions` object of a [`ReputationValue`]: the three dimensions
    /// the protocol defines, all required.
    ReputationDimensions {
        reliability: DimensionStats,
        task_quality: DimensionStats,
        policy_adherence: DimensionStats,
    }
);

wire!(
    /// The contextual reputation a snapshot carries.
    ReputationValue {
        context: ReputationContext,
        dimensions: ReputationDimensions,
        evidence_cutoff: i64,
        provenance_digest: Digest,
        scoring_artifact_digest: Digest,
        scoring_policy_revision: String,
        security_status: SecurityStatus,
        hold_refs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A signed reputation snapshot (typ `pact-reputation+jwt`).
    ReputationSnapshot {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        environment_id: String,
        holder_jkt: Digest,
        value: ReputationValue,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Ties an outcome to a native task and to a cause.
    Attribution {
        native_task_ref: String,
        independence_group: String,
        causal_assessment: CausalAssessment,
        assessment_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A signed execution outcome (typ `pact-outcome+jwt`).
    OutcomeReport {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        event_id: String,
        environment_id: String,
        task_id: String,
        operation_id: String,
        admission_receipt_id: Option<String>,
        observed_at: i64,
        reporter_role: ReporterRole,
        context: ReputationContext,
        event_kind: EventKind,
        result: OutcomeResult,
        dimension: Dimension,
        severity: Severity,
        evidence_refs: Vec<String>,
        attribution: Attribution,
        supersedes: Vec<String>,
        details: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// One control a learning policy lets artifacts adjust. `value_schema` is
    /// a JSON Schema object or boolean.
    AdaptiveControl {
        control_id: String,
        value_schema: serde_json::Value,
        allow_relaxation: bool,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The data-qualification part of a learning policy.
    DataPolicy {
        qualification_policy_id: String,
        ingestion_window_seconds: i64,
        positive_weight_cap_per_task: i64,
        maximum_failure_weight: i64,
        task_attribution_source: String,
        reporter_independence_policy_id: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A lower or upper bound on an evaluation metric.
    MetricBound {
        direction: BoundDirection,
        value: f64,
    }
);

wire!(
    /// The candidate-evaluation part of a learning policy.
    EvaluationPolicy {
        minimum_independent_tasks: i64,
        minimum_observation_seconds: i64,
        minimum_shadow_seconds: i64,
        holdout_policy_id: String,
        immutable_test_suite_digests: Vec<Digest>,
        metric_bounds: BTreeMap<String, MetricBound>,
        maximum_rollout_percent: i64,
        required_evaluator_ids: Vec<String>,
        rollback_condition_ids: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A signed learning policy (typ `pact-learning-policy+jwt`).
    LearningPolicy {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        policy_id: String,
        environment_id: String,
        mode: LearningMode,
        controller_ids: Vec<String>,
        base_revision: String,
        conservative_set: String,
        allowed_requirement_sets: Vec<String>,
        adaptive_fields: Vec<AdaptiveControl>,
        permitted_artifact_types: Vec<ArtifactType>,
        permitted_implementation_ids: Vec<String>,
        data_policy: DataPolicy,
        evaluation_policy: EvaluationPolicy,
        hold_clearance_authorities: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A learning artifact manifest (typ `pact-learning-artifact+jwt`).
    LearningArtifact {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        artifact_id: String,
        version: String,
        model_type: ArtifactType,
        implementation_id: String,
        content_digest: Digest,
        source_data_manifest_digest: Digest,
        feature_schema_digest: Digest,
        training_configuration_digest: Digest,
        evaluation_report_digest: Digest,
        intended_contexts: Vec<ReputationContext>,
        base_revision: String,
        parent_artifact_digest: Option<Digest>,
        output_controls: Vec<String>,
        artifact_store_ref: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// A learning lifecycle event (typ `pact-learning-event+jwt`).
    LearningEvent {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        event_id: String,
        environment_id: String,
        artifact_digest: Digest,
        previous_artifact_digest: Option<Digest>,
        policy_digest: Digest,
        transition: Transition,
        expected_state: LifecycleState,
        expected_active_digest: Option<Digest>,
        activate_artifact_digest: Option<Digest>,
        effective_at: i64,
        scope_contexts: Vec<ReputationContext>,
        evaluation_refs: Vec<String>,
        reason_codes: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Asks for a reputation snapshot.
    ReputationQuery {
        agent_id: String,
        holder_jkt: Digest,
        context: ReputationContext,
        audience: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Answers a submitted outcome or learning event.
    Acknowledgment {
        request_id: String,
        status: AckStatus,
        artifact_id: String,
        received_at: i64,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// One native protocol adapter of a gateway.
    NativeAdapter {
        protocol: String,
        version: String,
        mapping_revision: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The `endpoints` object of [`GatewayMetadata`]: the seven protocol
    /// endpoints, all required.
    GatewayEndpoints {
        requirements: String,
        evaluate: String,
        outcomes: String,
        reputation_query: String,
        learning_artifacts: String,
        learning_events: String,
        receipts_query: String,
    }
);

wire!(
    /// The document served at `/.well-known/pact-configuration`. `limits`
    /// maps a limit key (`max_json_depth`, ...) to its advertised value.
    /// `endpoints` and `jwks_uri` are required unless `extensions` holds
    /// `pact-transport-profile-v1` (draft 13.3.1, Appendix A.2).
    GatewayMetadata {
        gateway_id: String,
        environment_id: String,
        wire_versions: Vec<String>,
        jws_algorithms: Vec<JWSAlgorithm>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        endpoints: Option<GatewayEndpoints>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        jwks_uri: Option<String>,
        operation_mapping_version: String,
        extensions_supported: Vec<String>,
        modes: Vec<Mode>,
        presentation_transports: Vec<PresentationTransport>,
        limits: BTreeMap<String, i64>,
        protected_header_names: Vec<String>,
        header_normalization_id: String,
        adapters: Vec<NativeAdapter>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);
