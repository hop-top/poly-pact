use std::collections::HashMap;

use hop_top_pact::core::digest::object_digest_json;
use hop_top_pact::core::jws::p256::ecdsa::SigningKey;
use hop_top_pact::core::jws::{self, Header, KeySet, Role, StaticResolver, TYP_REQUIREMENTS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A requirement publisher signs a payload with its P-256 key (ES256).
    // Load the key from your key store; a fixed scalar keeps the example short.
    let key = SigningKey::from_slice(&[0x11; 32])?;
    let payload = br#"{"pact_version":"0.1","jti":"contract-1"}"#;
    let header = Header { typ: TYP_REQUIREMENTS.into(), kid: "publisher-1".into(), ..Header::default() };
    let compact = jws::sign(&header, payload, &key)?;

    // A gateway that trusts the publisher's public key verifies the compact JWS.
    let mut publisher = jws::public_jwk(key.verifying_key());
    publisher.kid = "publisher-1".into();
    let trusted = StaticResolver {
        key_sets: HashMap::from([(Role::RequirementPublisher, KeySet::new([publisher])?)]),
        ..StaticResolver::default()
    };
    let parsed = jws::verify(&compact, &trusted)?;
    println!("{} {} {}", parsed.role, parsed.header.kid, String::from_utf8(parsed.payload)?);

    // Object digest: unpadded base64url SHA-256 of the RFC 8785 canonical form.
    println!("{}", object_digest_json(br#"{"jti":"contract-1","pact_version":"0.1"}"#)?);
    Ok(())
}
