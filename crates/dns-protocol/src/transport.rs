//! DNS transport payload contracts (Sprint 0.8).
//!
//! This module defines payload-level contracts for DoH, DoT, and DoQ transports.
//! It does NOT implement any async transport — only the DNS message boundaries
//! and encoding rules for each transport type.
//!
//! - **DoH** (RFC 8484): DNS messages are carried as `application/dns-message`
//!   in HTTP request/response bodies, base64url-encoded for GET queries.
//! - **DoT** (RFC 7858): Uses standard TCP framing (2-byte length prefix)
//!   over a TLS connection. The framing layer is identical to TCP DNS.
//! - **DoQ** (RFC 9250): DNS messages are carried over QUIC streams/datagrams
//!   without a length prefix (QUIC itself handles framing).

use crate::tcp_frame;

// ─── DoH (RFC 8484) ─────────────────────────────────────────────────

/// DoH content type for DNS messages.
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// Encode a DNS message for DoH GET query (base64url without padding).
///
/// Per RFC 8484 Section 2.1, the DNS wire format message is base64url-encoded
/// without padding and passed as the `dns` query parameter.
#[must_use]
pub fn doh_encode_get(dns_message: &[u8]) -> String {
    b64url::encode(dns_message)
}

/// Decode a DNS message from DoH GET query parameter (base64url).
pub fn doh_decode_get(encoded: &str) -> Result<Vec<u8>, DohError> {
    b64url::decode(encoded).map_err(|_| DohError::InvalidBase64Url)
}

/// Encode a DNS message for DoH POST body.
///
/// Per RFC 8484 Section 4.1, the POST body is the raw DNS wire format message
/// with Content-Type `application/dns-message`.
#[must_use]
pub fn doh_encode_post(dns_message: &[u8]) -> Vec<u8> {
    dns_message.to_vec()
}

/// Decode a DNS message from DoH POST body.
pub fn doh_decode_post(body: &[u8]) -> Result<Vec<u8>, DohError> {
    if body.is_empty() {
        return Err(DohError::EmptyBody);
    }
    Ok(body.to_vec())
}

/// Errors specific to DoH payload handling.
#[derive(Debug, thiserror::Error)]
pub enum DohError {
    /// Invalid base64url encoding in DoH GET parameter.
    #[error("invalid base64url encoding")]
    InvalidBase64Url,
    /// Empty DoH POST body.
    #[error("empty DoH body")]
    EmptyBody,
}

// ─── DoT (RFC 7858) ─────────────────────────────────────────────────

/// DoT uses the same TCP length-prefix framing.
///
/// The only difference from plain TCP DNS is that the transport is TLS.
/// For wire-level purposes, DoT frames are identical to TCP frames.

/// Encode a DNS message for DoT transport (same as TCP).
#[must_use]
pub fn dot_encode_frame(dns_message: &[u8]) -> Vec<u8> {
    tcp_frame::encode_tcp_frame(dns_message)
}

/// Decode a DNS message from DoT transport (same as TCP).
pub fn dot_decode_frame(
    data: &[u8],
    max_frame_size: u16,
) -> Result<(&[u8], usize), dns_types::ProtocolError> {
    tcp_frame::decode_tcp_frame(data, max_frame_size)
}

// ─── DoQ (RFC 9250) ─────────────────────────────────────────────────

/// DoQ carries DNS messages directly on QUIC streams without length prefix.
///
/// Per RFC 9250 Section 4.2, a DoQ message is a single DNS message in
/// wire format, sent as the content of a QUIC stream. No additional framing.

/// Encode a DNS message for DoQ transport (raw wire format, no prefix).
#[must_use]
pub fn doq_encode(dns_message: &[u8]) -> Vec<u8> {
    dns_message.to_vec()
}

/// Decode a DNS message from DoQ transport (raw wire format).
pub fn doq_decode(data: &[u8]) -> Result<Vec<u8>, DohError> {
    if data.is_empty() {
        return Err(DohError::EmptyBody);
    }
    Ok(data.to_vec())
}

// ─── Minimal base64url codec (no external dependency) ────────────────

const B64URL_CHARSET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

mod b64url {
    use super::B64URL_CHARSET;

    /// Encode bytes to base64url without padding.
    #[must_use]
    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(B64URL_CHARSET[((triple >> 18) & 0x3F) as usize] as char);
            result.push(B64URL_CHARSET[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(B64URL_CHARSET[((triple >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                result.push(B64URL_CHARSET[(triple & 0x3F) as usize] as char);
            }
        }
        result
    }

    /// Decode base64url string to bytes.
    pub fn decode(encoded: &str) -> Result<Vec<u8>, B64UrlError> {
        // Pad to multiple of 4.
        let padded_len = (encoded.len() + 3) & !3;
        let mut padded = String::with_capacity(padded_len);
        padded.push_str(encoded);
        while padded.len() < padded_len {
            padded.push('=');
        }

        let standard: String = padded
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();

        let bytes = standard.as_bytes();
        let mut result = Vec::with_capacity(encoded.len() * 3 / 4);

        for chunk in bytes.chunks(4) {
            if chunk.len() != 4 {
                return Err(B64UrlError::InvalidLength);
            }

            let mut values = [0u32; 4];
            for (i, &c) in chunk.iter().enumerate() {
                values[i] = match c {
                    b'A'..=b'Z' => (c - b'A') as u32,
                    b'a'..=b'z' => (c - b'a' + 26) as u32,
                    b'0'..=b'9' => (c - b'0' + 52) as u32,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => continue,
                    _ => return Err(B64UrlError::InvalidChar(c)),
                };
            }

            let triple = (values[0] << 18) | (values[1] << 12) | (values[2] << 6) | values[3];
            result.push(((triple >> 16) & 0xFF) as u8);
            if chunk[2] != b'=' {
                result.push(((triple >> 8) & 0xFF) as u8);
            }
            if chunk[3] != b'=' {
                result.push((triple & 0xFF) as u8);
            }
        }

        Ok(result)
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub enum B64UrlError {
        InvalidLength,
        InvalidChar(u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── DoH tests ─────────────────────────────────────────────────

    #[test]
    fn test_doh_get_roundtrip() {
        let msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01];
        let encoded = doh_encode_get(&msg);
        let decoded = doh_decode_get(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_doh_get_empty() {
        let encoded = doh_encode_get(&[]);
        let decoded = doh_decode_get(&encoded).unwrap();
        assert_eq!(decoded, vec![]);
    }

    #[test]
    fn test_doh_post_roundtrip() {
        let msg = vec![0xAB, 0xCD, 0xEF];
        let body = doh_encode_post(&msg);
        assert_eq!(body, msg);
        let decoded = doh_decode_post(&body).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_doh_post_empty_body() {
        assert!(doh_decode_post(&[]).is_err());
    }

    #[test]
    fn test_doh_invalid_base64url() {
        assert!(doh_decode_get("not!valid!base64!!!").is_err());
    }

    // ─── DoT tests ─────────────────────────────────────────────────

    #[test]
    fn test_dot_frame_matches_tcp() {
        let msg = vec![0x01, 0x02, 0x03];
        let dot_frame = dot_encode_frame(&msg);
        let tcp_frame_encoded = tcp_frame::encode_tcp_frame(&msg);
        assert_eq!(dot_frame, tcp_frame_encoded);
    }

    #[test]
    fn test_dot_decode_frame() {
        let msg = vec![0xAA, 0xBB];
        let frame = dot_encode_frame(&msg);
        let (decoded, _) = dot_decode_frame(&frame, tcp_frame::DEFAULT_MAX_TCP_FRAME).unwrap();
        assert_eq!(decoded, &msg[..]);
    }

    // ─── DoQ tests ─────────────────────────────────────────────────

    #[test]
    fn test_doq_encode_is_raw() {
        let msg = vec![0x12, 0x34, 0x56, 0x78];
        let encoded = doq_encode(&msg);
        assert_eq!(encoded, msg); // No framing added.
    }

    #[test]
    fn test_doq_decode_roundtrip() {
        let msg = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = doq_encode(&msg);
        let decoded = doq_decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_doq_decode_empty() {
        assert!(doq_decode(&[]).is_err());
    }

    // ─── Base64URL tests ───────────────────────────────────────────

    #[test]
    fn test_base64url_encode_decode() {
        let data = b"Hello, DNS world!";
        let encoded = b64url::encode(data);
        let decoded = b64url::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_no_padding() {
        let data = b"test";
        let encoded = b64url::encode(data);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_base64url_special_chars() {
        let data = [0xFB, 0xFF, 0xFE]; // Will produce non-alphanumeric chars.
        let encoded = b64url::encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = b64url::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_empty() {
        let encoded = b64url::encode(b"");
        let decoded = b64url::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    // ─── Payload contract tests ────────────────────────────────────

    #[test]
    fn test_transport_content_type() {
        assert_eq!(DOH_CONTENT_TYPE, "application/dns-message");
    }

    #[test]
    fn test_doh_post_is_raw_wire() {
        let wire = vec![0x00, 0x01, 0x02, 0x03];
        let body = doh_encode_post(&wire);
        assert_eq!(body, wire);
    }

    #[test]
    fn test_doq_no_framing() {
        let wire = vec![0x12, 0x34, 0x56, 0x78, 0x9A];
        let doq = doq_encode(&wire);
        assert_eq!(doq.len(), wire.len());
        assert_eq!(doq, wire);
    }
}
