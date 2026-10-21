//! The string enums of the wire objects. Each is an open newtype over the
//! JSON string, as in the Go reference: decoding keeps any string, and
//! `is_valid` reports whether it is one of the values the draft defines.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! string_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $konst:ident = $value:literal,)+ }) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            $($(#[$vdoc])* pub const $konst: $name = $name(Cow::Borrowed($value));)+

            /// The values the draft defines, in its order.
            pub const VALUES: &'static [$name] = &[$($name::$konst),+];

            /// A value from its JSON string, defined or not.
            pub fn new(s: impl Into<String>) -> $name {
                $name(Cow::Owned(s.into()))
            }

            /// The JSON string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether the value is one the draft defines.
            pub fn is_valid(&self) -> bool {
                Self::VALUES.contains(self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> $name {
                $name::new(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<$name, D::Error> {
                String::deserialize(d).map($name::new)
            }
        }
    };
}

/// The wire version of the protocol: `pact_version` of every signed artifact.
pub const VERSION: &str = "0.1";

string_enum!(
    /// Where a field rule takes its value from.
    RuleSource { SELF = "self", EVIDENCE = "evidence", NATIVE = "native", }
);
string_enum!(
    /// How a field rule compares a value.
    Comparison { EQUAL = "equal", SUBSET = "subset", }
);
string_enum!(
    /// The enforcement mode of a contract or an admission.
    Mode { ENFORCED = "enforced", OBSERVE = "observe", }
);
string_enum!(
    /// The kind of an evidence artifact.
    EvidenceKind {
        IDENTITY = "identity", MEMBERSHIP = "membership", DELEGATION = "delegation",
        RUNTIME = "runtime", CAPABILITY = "capability", APPROVAL = "approval",
    }
);
string_enum!(
    /// The result of one admission check.
    CheckStatus { PASS = "PASS", FAIL = "FAIL", UNKNOWN = "UNKNOWN", NOT_APPLICABLE = "NOT_APPLICABLE", }
);
string_enum!(
    /// The admission decision.
    Decision { ADMISSIBLE = "ADMISSIBLE", INADMISSIBLE = "INADMISSIBLE", DEFERRED = "DEFERRED", }
);
string_enum!(
    /// Why an admission ended.
    TerminalReason { COMPLETED = "COMPLETED", CANCELLED = "CANCELLED", EXPIRED = "EXPIRED", }
);
string_enum!(
    /// The security status of a reputation value.
    SecurityStatus { CLEAR = "CLEAR", CAUTION = "CAUTION", HOLD = "HOLD", UNKNOWN = "UNKNOWN", }
);
string_enum!(
    /// Who caused an outcome.
    CausalAssessment { AGENT = "AGENT", ENVIRONMENT = "ENVIRONMENT", MIXED = "MIXED", UNKNOWN = "UNKNOWN", }
);
string_enum!(
    /// The role of an outcome reporter.
    ReporterRole {
        GATEWAY = "gateway", EXECUTOR = "executor", EVALUATOR = "evaluator",
        TASK_OWNER = "task_owner", SECURITY_AUTHORITY = "security_authority", AGENT = "agent",
    }
);
string_enum!(
    /// The kind of an outcome event.
    EventKind {
        ADMISSION = "ADMISSION", AUTHORIZATION = "AUTHORIZATION", EXECUTION = "EXECUTION", QUALITY = "QUALITY",
        SECURITY = "SECURITY", FEEDBACK = "FEEDBACK", CORRECTION = "CORRECTION", REMEDIATION = "REMEDIATION",
    }
);
string_enum!(
    /// The result of an outcome.
    OutcomeResult { SUCCESS = "SUCCESS", FAILURE = "FAILURE", UNKNOWN = "UNKNOWN", NOT_APPLICABLE = "NOT_APPLICABLE", }
);
string_enum!(
    /// The reputation dimension an outcome counts toward.
    Dimension {
        RELIABILITY = "reliability", TASK_QUALITY = "task_quality",
        POLICY_ADHERENCE = "policy_adherence", NONE = "none",
    }
);
string_enum!(
    /// The severity of an outcome.
    Severity { INFO = "info", LOW = "low", MEDIUM = "medium", HIGH = "high", CRITICAL = "critical", }
);
string_enum!(
    /// The direction of a metric bound.
    BoundDirection { LOWER = "lower", UPPER = "upper", }
);
string_enum!(
    /// The mode of a learning policy.
    LearningMode { OBSERVE = "observe", BOUNDED_AUTONOMOUS = "bounded_autonomous", }
);
string_enum!(
    /// The type of a learning artifact.
    ArtifactType {
        BASELINE = "baseline", SCORE = "score", REQUIREMENT_SELECTOR = "requirement_selector",
        CALIBRATOR = "calibrator", ASSESSMENT = "assessment",
    }
);
string_enum!(
    /// A learning lifecycle transition.
    Transition {
        EVALUATED = "EVALUATED", SHADOW = "SHADOW", ACTIVE = "ACTIVE",
        FROZEN = "FROZEN", ROLLED_BACK = "ROLLED_BACK", RETIRED = "RETIRED",
    }
);
string_enum!(
    /// A learning lifecycle state.
    LifecycleState {
        CANDIDATE = "CANDIDATE", EVALUATED = "EVALUATED", SHADOW = "SHADOW", ACTIVE = "ACTIVE",
        FROZEN = "FROZEN", ROLLED_BACK = "ROLLED_BACK", RETIRED = "RETIRED",
    }
);
string_enum!(
    /// The status of an acknowledgment.
    AckStatus { ACCEPTED = "ACCEPTED", DUPLICATE = "DUPLICATE", }
);
string_enum!(
    /// A JWS algorithm a gateway advertises.
    JWSAlgorithm { ES256 = "ES256", ED25519 = "Ed25519", }
);
string_enum!(
    /// How a presentation reaches a gateway.
    PresentationTransport {
        HEADER = "header", GATEWAY_EVALUATE = "gateway-evaluate", ADAPTER_ENVELOPE = "adapter-envelope",
    }
);
