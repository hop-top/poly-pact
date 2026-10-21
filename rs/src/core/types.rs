//! The wire objects of draft Appendix A.3: profiles, intents, operations,
//! requirement contracts, evidence, presentations and admission receipts.
//!
//! There is one struct per `$defs` entry of the vendored schema, with the
//! same member names as field names (`r#type` for `type`), as in the Go
//! reference. Every struct decodes with `deny_unknown_fields` and `default`:
//! a member the input leaves out keeps its zero value, and the schema decides
//! whether it was required. The optional members (the open `extensions`
//! object, and `endpoints` and `jwks_uri` of [`GatewayMetadata`]) are `Option`
//! and are written only when present; `null` is rejected for them. A
//! nullable member is an `Option` that is written as `null` when `None`.
//!
//! Decode untrusted input with [`crate::core::strictjson`]. The types do not
//! enforce patterns, lengths or numeric ranges, and they do not produce
//! digests: compute `object_digest` over the received JSON, never over a
//! re-encoded struct.

use serde::{Deserialize, Deserializer};

use super::enums::*;
use super::{Digest, Object};

/// Deserializes an optional member that may be absent but never `null`.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

macro_rules! wire {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $field:ident : $ty:ty,)* }) => {
        $(#[$m])*
        #[derive(Clone, Debug, Default, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $name { $($(#[$fm])* pub $field: $ty,)* }
    };
}
pub(crate) use wire;

wire!(
    /// An agent's enrolled profile.
    AgentProfile {
        profile_id: String,
        revision: i64,
        agent_id: String,
        operator_id: String,
        tenant_id: String,
        holder_jkt: Digest,
        created_at: i64,
        expires_at: i64,
        attributes: Object,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The declared intent of an operation.
    Intent {
        intent_id: String,
        purpose_id: String,
        description: String,
        task_id: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The operation a gateway derives from a real request.
    OperationContext {
        operation_id: String,
        environment_id: String,
        principal_id: String,
        action: String,
        resources: Vec<String>,
        method: String,
        target_uri: String,
        body_digest: Digest,
        headers: std::collections::BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// One requirement a contract places on a profile field. `schema` is a
    /// restricted JSON Schema object or boolean.
    FieldRule {
        rule_id: String,
        path: String,
        schema: serde_json::Value,
        source: RuleSource,
        comparison: Comparison,
        allowed_issuers: Vec<String>,
        native_path: Option<String>,
        max_age_seconds: i64,
        status_max_age_seconds: i64,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The effective requirement contract (typ `pact-requirements+jwt`).
    RequirementContract {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        contract_id: String,
        environment_id: String,
        holder_jkt: Digest,
        operation_digest: Digest,
        intent_digest: Digest,
        base_revision: String,
        selected_set: String,
        field_rules: Vec<FieldRule>,
        context_checks: Vec<String>,
        learning_policy_digest: Digest,
        learning_artifact_digest: Digest,
        nonce: String,
        mode: Mode,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// One claim of an evidence artifact. `value` is any JSON value.
    Claim {
        path: String,
        value: serde_json::Value,
    }
);

wire!(
    /// An evidence artifact (typ `pact-evidence+jwt`).
    Evidence {
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
        kind: EvidenceKind,
        claims: Vec<Claim>,
        status_ref: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// An agent presentation (typ `pact-presentation+jwt`). `contract`,
    /// `evidence` and `reputation` hold compact JWS strings.
    Presentation {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        contract: String,
        profile: AgentProfile,
        intent: Intent,
        operation: OperationContext,
        evidence: Vec<String>,
        reputation: Option<String>,
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The outcome of one admission check.
    CheckResult {
        check_id: String,
        result: CheckStatus,
        reason_code: String,
        checked_at: i64,
        source_observed_at: Option<i64>,
        status_checked_at: Option<i64>,
        evidence_ids: Vec<String>,
        source_id: String,
        source_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The signed admission receipt (typ `pact-admission+jwt`).
    AdmissionAttestation {
        pact_version: String,
        iss: String,
        sub: String,
        aud: String,
        jti: String,
        iat: i64,
        nbf: i64,
        exp: i64,
        tenant_id: String,
        presentation_id: String,
        operation_id: String,
        principal_id: String,
        environment_id: String,
        holder_jkt: Digest,
        profile_digest: Digest,
        intent_digest: Digest,
        operation_digest: Digest,
        requirements_digest: Digest,
        learning_policy_digest: Digest,
        learning_artifact_digest: Digest,
        decision: Decision,
        terminal_reason: TerminalReason,
        mode: Mode,
        checks: Vec<CheckResult>,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Asks a gateway for a requirement contract.
    ContractRequest {
        agent_id: String,
        holder_jkt: Digest,
        intent: Intent,
        operation: OperationContext,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Asks a gateway to evaluate a presentation, a compact JWS, against the
    /// operation that is about to run.
    EvaluationRequest {
        presentation: String,
        actual_operation: OperationContext,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// Asks for an admission receipt.
    ReceiptQuery {
        receipt_id: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);

wire!(
    /// The error body of the transport (RFC 9457 shape).
    Problem {
        r#type: String,
        title: String,
        status: i64,
        code: String,
        request_id: String,
        #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        extensions: Option<Object>,
    }
);
