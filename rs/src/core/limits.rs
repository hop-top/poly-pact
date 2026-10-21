//! The resource limits of draft section 20.1.

use std::fmt;

use super::strictjson;
use super::{Intent, OperationContext, Presentation, RequirementContract};

/// The metadata keys of the baseline limits that section 20.1 names in
/// `GatewayMetadata.limits`. A [`LimitError`] carries one of them.
pub const KEY_MAX_PRESENTATION_BYTES: &str = "max_presentation_bytes";
pub const KEY_MAX_ARTIFACT_PAYLOAD_BYTES: &str = "max_artifact_payload_bytes";
pub const KEY_MAX_PROFILE_BYTES: &str = "max_profile_bytes";
pub const KEY_MAX_EVIDENCE_ARTIFACTS: &str = "max_evidence_artifacts";
pub const KEY_MAX_FIELD_RULES: &str = "max_field_rules";
pub const KEY_MAX_JSON_DEPTH: &str = "max_json_depth";
pub const KEY_MAX_RESOURCES: &str = "max_resources";
pub const KEY_MAX_DESCRIPTION_BYTES: &str = "max_description_bytes";

const BASELINE: Limits = Limits {
    presentation_bytes: 256 << 10,
    artifact_payload_bytes: 32 << 10,
    profile_bytes: 32 << 10,
    evidence_artifacts: 32,
    field_rules: 128,
    depth: 16,
    resources: 256,
    description_bytes: 4096,
};

/// Why a limit check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// An object is larger or has more members than a limit allows.
    Exceeded,
    /// A [`Limits`] value is not positive or is looser than the baseline.
    Invalid,
}

/// The limit that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitError {
    pub kind: LimitKind,
    /// The section 20.1 metadata key of the limit, such as `max_json_depth`.
    pub key: &'static str,
    /// What the limit allows: the configured value for
    /// [`LimitKind::Exceeded`], the baseline for [`LimitKind::Invalid`].
    pub max: usize,
    /// The offending value: the measured quantity, or the configured limit
    /// that is out of range.
    pub got: usize,
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            LimitKind::Invalid => {
                write!(f, "core: invalid limits: {} is {}, must be 1..{}", self.key, self.got, self.max)
            }
            LimitKind::Exceeded => {
                write!(f, "core: limit exceeded: {} is {}, at most {}", self.key, self.got, self.max)
            }
        }
    }
}

impl std::error::Error for LimitError {}

/// The resource limits a validator enforces on untrusted input (section
/// 20.1). [`Limits::default`] is the baseline; a deployment may configure
/// tighter values, and [`Limits::check`] rejects looser ones.
///
/// The nesting depth is enforced while decoding, by strictjson; the
/// `validate_*` methods check the rest on decoded objects. Byte limits apply
/// to the received bytes, not to a re-encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The largest decoded presentation, embedded artifacts included.
    pub presentation_bytes: usize,
    /// The largest decoded payload of one evidence or reputation artifact.
    pub artifact_payload_bytes: usize,
    /// The largest profile JSON.
    pub profile_bytes: usize,
    /// The most evidence artifacts in a presentation.
    pub evidence_artifacts: usize,
    /// The most field rules in a contract.
    pub field_rules: usize,
    /// The deepest JSON nesting; the outermost object or array has depth 1.
    pub depth: usize,
    /// The most resources in an operation.
    pub resources: usize,
    /// The longest human-readable description in UTF-8 bytes.
    pub description_bytes: usize,
}

impl Default for Limits {
    /// The baseline limits of section 20.1.
    fn default() -> Limits {
        BASELINE
    }
}

fn exceeds(key: &'static str, got: usize, max: usize) -> Result<(), LimitError> {
    if got > max {
        return Err(LimitError { kind: LimitKind::Exceeded, key, max, got });
    }
    Ok(())
}

impl Limits {
    /// The baseline limits of section 20.1.
    pub fn defaults() -> Limits {
        BASELINE
    }

    /// Checks that every limit is at least 1 and no larger than its
    /// baseline. A zero limit is an error, not an unlimited input.
    pub fn check(&self) -> Result<(), LimitError> {
        let b = BASELINE;
        for (key, value, ceiling) in [
            (KEY_MAX_PRESENTATION_BYTES, self.presentation_bytes, b.presentation_bytes),
            (KEY_MAX_ARTIFACT_PAYLOAD_BYTES, self.artifact_payload_bytes, b.artifact_payload_bytes),
            (KEY_MAX_PROFILE_BYTES, self.profile_bytes, b.profile_bytes),
            (KEY_MAX_EVIDENCE_ARTIFACTS, self.evidence_artifacts, b.evidence_artifacts),
            (KEY_MAX_FIELD_RULES, self.field_rules, b.field_rules),
            (KEY_MAX_JSON_DEPTH, self.depth, b.depth),
            (KEY_MAX_RESOURCES, self.resources, b.resources),
            (KEY_MAX_DESCRIPTION_BYTES, self.description_bytes, b.description_bytes),
        ] {
            if value < 1 || value > ceiling {
                return Err(LimitError { kind: LimitKind::Invalid, key, max: ceiling, got: value });
            }
        }
        Ok(())
    }

    /// Checks a decoded presentation: `size` is the length in bytes of the
    /// decoded presentation, embedded artifacts included. Returns the first
    /// limit exceeded among the size, the evidence count, the resources and
    /// the description.
    pub fn validate_presentation(&self, p: &Presentation, size: usize) -> Result<(), LimitError> {
        exceeds(KEY_MAX_PRESENTATION_BYTES, size, self.presentation_bytes)?;
        exceeds(KEY_MAX_EVIDENCE_ARTIFACTS, p.evidence.len(), self.evidence_artifacts)?;
        self.validate_operation(&p.operation)?;
        self.validate_intent(&p.intent)
    }

    /// Checks the number of field rules of a decoded contract.
    pub fn validate_contract(&self, c: &RequirementContract) -> Result<(), LimitError> {
        exceeds(KEY_MAX_FIELD_RULES, c.field_rules.len(), self.field_rules)
    }

    /// Checks the number of resources of a decoded operation.
    pub fn validate_operation(&self, op: &OperationContext) -> Result<(), LimitError> {
        exceeds(KEY_MAX_RESOURCES, op.resources.len(), self.resources)
    }

    /// Checks the length in UTF-8 bytes of an intent's description.
    pub fn validate_intent(&self, intent: &Intent) -> Result<(), LimitError> {
        exceeds(KEY_MAX_DESCRIPTION_BYTES, intent.description.len(), self.description_bytes)
    }

    /// Checks the decoded payload size of one evidence or reputation artifact.
    pub fn validate_artifact_size(&self, size: usize) -> Result<(), LimitError> {
        exceeds(KEY_MAX_ARTIFACT_PAYLOAD_BYTES, size, self.artifact_payload_bytes)
    }

    /// Checks the size in bytes of a profile's JSON.
    pub fn validate_profile_size(&self, size: usize) -> Result<(), LimitError> {
        exceeds(KEY_MAX_PROFILE_BYTES, size, self.profile_bytes)
    }

    /// The strictjson limits for decoding a presentation.
    pub fn presentation_json(&self) -> strictjson::Limits {
        strictjson::Limits { max_bytes: self.presentation_bytes, max_depth: self.depth }
    }

    /// The strictjson limits for decoding the payload of one evidence or
    /// reputation artifact.
    pub fn artifact_json(&self) -> strictjson::Limits {
        strictjson::Limits { max_bytes: self.artifact_payload_bytes, max_depth: self.depth }
    }

    /// The strictjson limits for decoding a profile.
    pub fn profile_json(&self) -> strictjson::Limits {
        strictjson::Limits { max_bytes: self.profile_bytes, max_depth: self.depth }
    }
}
