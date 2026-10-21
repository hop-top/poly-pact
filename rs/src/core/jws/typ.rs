//! The algorithms, signer roles and `typ` values of the profile (draft 7.2
//! and 7.3).

use std::fmt;

/// The baseline algorithm, ECDSA P-256 with SHA-256 (RFC 7518 section 3.4).
pub const ALG_ES256: &str = "ES256";

/// The fully specified Ed25519 identifier (RFC 9864 section 2.2). The draft
/// makes Ed25519 optional; this SDK does not implement it, so no header or
/// key of this algorithm is ever accepted.
pub const ALG_ED25519: &str = "Ed25519";

/// The signer role a `typ` requires, after the "Required signer" column of
/// the draft 7.3 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// A gateway-authorized requirement publisher.
    RequirementPublisher,
    /// An evidence issuer authorized for its claim paths and scope.
    Issuer,
    /// The enrolled agent holder key: the only role whose key comes from the
    /// artifact (an embedded `jwk` matching `holder_jkt`).
    Holder,
    /// A gateway-authorized validator.
    Validator,
    /// A reporter authorized for the observation type.
    Reporter,
    /// An authorized reputation service.
    ReputationService,
    /// A native administrator or delegated policy authority.
    PolicyAuthority,
    /// A learning controller.
    LearningController,
}

impl Role {
    /// The role's name in the draft.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::RequirementPublisher => "requirement-publisher",
            Role::Issuer => "issuer",
            Role::Holder => "holder",
            Role::Validator => "validator",
            Role::Reporter => "reporter",
            Role::ReputationService => "reputation-service",
            Role::PolicyAuthority => "policy-authority",
            Role::LearningController => "learning-controller",
        }
    }

    /// The role of a name, as the draft and the vectors write it.
    pub fn parse(s: &str) -> Option<Role> {
        TYP_TABLE.iter().map(|r| r.1).find(|r| r.as_str() == s)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const TYP_REQUIREMENTS: &str = "pact-requirements+jwt";
pub const TYP_EVIDENCE: &str = "pact-evidence+jwt";
pub const TYP_PRESENTATION: &str = "pact-presentation+jwt";
pub const TYP_ADMISSION: &str = "pact-admission+jwt";
pub const TYP_OUTCOME: &str = "pact-outcome+jwt";
pub const TYP_REPUTATION: &str = "pact-reputation+jwt";
pub const TYP_LEARNING_POLICY: &str = "pact-learning-policy+jwt";
pub const TYP_LEARNING_ARTIFACT: &str = "pact-learning-artifact+jwt";
pub const TYP_LEARNING_EVENT: &str = "pact-learning-event+jwt";

/// The draft 7.3 table, in its order.
const TYP_TABLE: [(&str, Role); 9] = [
    (TYP_REQUIREMENTS, Role::RequirementPublisher),
    (TYP_EVIDENCE, Role::Issuer),
    (TYP_PRESENTATION, Role::Holder),
    (TYP_ADMISSION, Role::Validator),
    (TYP_OUTCOME, Role::Reporter),
    (TYP_REPUTATION, Role::ReputationService),
    (TYP_LEARNING_POLICY, Role::PolicyAuthority),
    (TYP_LEARNING_ARTIFACT, Role::LearningController),
    (TYP_LEARNING_EVENT, Role::LearningController),
];

/// The signer role the draft 7.3 table requires for `typ`, compared exactly.
pub fn typ_role(typ: &str) -> Option<Role> {
    TYP_TABLE.iter().find(|row| row.0 == typ).map(|row| row.1)
}

/// The `typ` values of the draft 7.3 table, in its order.
pub fn typs() -> Vec<&'static str> {
    TYP_TABLE.iter().map(|row| row.0).collect()
}
