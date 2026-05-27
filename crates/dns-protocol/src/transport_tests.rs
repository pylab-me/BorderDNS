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
