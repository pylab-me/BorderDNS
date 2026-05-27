use super::*;

#[test]
fn test_encode_tcp_frame() {
    let dns_msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01];
    let frame = encode_tcp_frame(&dns_msg);
    assert_eq!(frame.len(), 2 + 6);
    assert_eq!(frame[0], 0x00);
    assert_eq!(frame[1], 0x06);
    assert_eq!(&frame[2..], &dns_msg);
}

#[test]
fn test_decode_tcp_frame_roundtrip() {
    let dns_msg = vec![0xAB, 0xCD, 0x01, 0x00];
    let frame = encode_tcp_frame(&dns_msg);
    let (decoded, consumed) = decode_tcp_frame(&frame, DEFAULT_MAX_TCP_FRAME).unwrap();
    assert_eq!(decoded, &dns_msg[..]);
    assert_eq!(consumed, 2 + 4);
}

#[test]
fn test_decode_tcp_frame_trailing_data() {
    let dns_msg = vec![0x01, 0x02];
    let frame = encode_tcp_frame(&dns_msg);
    let dns_msg2 = vec![0x03, 0x04];
    let frame2 = encode_tcp_frame(&dns_msg2);
    let mut data = frame;
    data.extend_from_slice(&frame2);

    let (decoded, consumed) = decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).unwrap();
    assert_eq!(decoded, &dns_msg[..]);
    assert_eq!(consumed, 4); // Only the first frame.

    // Decode second frame.
    let (decoded2, consumed2) = decode_tcp_frame(&data[consumed..], DEFAULT_MAX_TCP_FRAME).unwrap();
    assert_eq!(decoded2, &dns_msg2[..]);
    assert_eq!(consumed2, 4);
}

#[test]
fn test_decode_tcp_frame_too_short() {
    let data = [0x00];
    assert!(decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).is_err());
}

#[test]
fn test_decode_tcp_frame_incomplete() {
    // Length says 10 bytes, but only 3 bytes of message follow.
    let data = [0x00, 0x0A, 0x01, 0x02, 0x03];
    assert!(decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).is_err());
}

#[test]
fn test_decode_tcp_frame_exceeds_limit() {
    // Length says 100 bytes.
    let mut data = vec![0x00, 100];
    data.extend_from_slice(&vec![0; 100]);
    assert!(decode_tcp_frame(&data, 50).is_err());
}

#[test]
fn test_tcp_frame_decoder_streaming() {
    let mut decoder = TcpFrameDecoder::new();

    let msg1 = vec![0xAA, 0xBB];
    let msg2 = vec![0xCC, 0xDD, 0xEE];
    let frame1 = encode_tcp_frame(&msg1);
    let frame2 = encode_tcp_frame(&msg2);

    // Feed partial frame 1.
    decoder.feed(&frame1[..3]);
    assert!(decoder.try_decode().unwrap().is_none());

    // Feed rest of frame 1.
    decoder.feed(&frame1[3..]);
    let (msg, _) = decoder.try_decode().unwrap().unwrap();
    assert_eq!(msg, &msg1[..]);

    // Feed both bytes of frame2 at once.
    decoder.feed(&frame2);
    let (msg, _) = decoder.try_decode().unwrap().unwrap();
    assert_eq!(msg, &msg2[..]);
}

#[test]
fn test_tcp_frame_decoder_multiple_frames_in_buffer() {
    let mut decoder = TcpFrameDecoder::new();

    let msg1 = vec![0x01, 0x02];
    let msg2 = vec![0x03, 0x04, 0x05];
    let mut combined = encode_tcp_frame(&msg1);
    combined.extend_from_slice(&encode_tcp_frame(&msg2));

    decoder.feed(&combined);

    let (msg, _) = decoder.try_decode().unwrap().unwrap();
    assert_eq!(msg, &msg1[..]);
    assert_eq!(decoder.buffered(), 5); // frame2 still buffered (2 prefix + 3 data)

    let (msg, _) = decoder.try_decode().unwrap().unwrap();
    assert_eq!(msg, &msg2[..]);
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn test_decode_tcp_frames_bulk() {
    let msg1 = vec![0x01, 0x02];
    let msg2 = vec![0x03, 0x04];
    let mut data = encode_tcp_frame(&msg1);
    data.extend_from_slice(&encode_tcp_frame(&msg2));

    let (messages, consumed) = decode_tcp_frames(&data, DEFAULT_MAX_TCP_FRAME).unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0], &msg1[..]);
    assert_eq!(messages[1], &msg2[..]);
    assert_eq!(consumed, data.len());
}

#[test]
fn test_max_frame_size_boundary() {
    // Exactly at limit should work.
    let mut data = vec![0x00, 10]; // length = 10
    data.extend_from_slice(&vec![0; 10]);
    let result = decode_tcp_frame(&data, 10);
    assert!(result.is_ok());

    // Over limit should fail.
    let mut data2 = vec![0x00, 11]; // length = 11
    data2.extend_from_slice(&vec![0; 11]);
    let result2 = decode_tcp_frame(&data2, 10);
    assert!(result2.is_err());
}
