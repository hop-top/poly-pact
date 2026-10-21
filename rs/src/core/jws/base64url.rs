//! RFC 7515 base64url: the URL-safe alphabet, no padding, no white space,
//! and only the canonical encoding of its octets (RFC 4648 section 3.5).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Decodes `s` as RFC 7515 base64url, or says why it is not.
pub(crate) fn decode_segment(s: &str) -> Result<Vec<u8>, String> {
    if let Some((i, c)) = s.bytes().enumerate().find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_'))
    {
        return Err(format!("character {:?} at offset {i} is not base64url", c as char));
    }
    URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())
}

/// Encodes `b` as unpadded base64url.
pub(crate) fn encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_forms() {
        for s in ["AA==", "A+/A", "AA\nAA", "AB", "A", "AAAAA", "é", "AA AA"] {
            assert!(decode_segment(s).is_err(), "{s:?} decoded");
        }
        assert_eq!(decode_segment("").unwrap(), b"");
        assert_eq!(decode_segment("AA").unwrap(), [0]);
        assert_eq!(decode_segment("_-8").unwrap(), [0xff, 0xef]);
        assert_eq!(encode(&[0xff, 0xef]), "_-8");
    }
}
