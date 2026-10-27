use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use sha2::{Digest, Sha256};
use uu_linux_client::protocol::{
    AuthRequest, AuthResponse, EncryptionMethod, ForwardVersion, MessageType, ProtocolError,
    decode_auth_response, decode_forward_payload, decode_post_auth_frame, derive_proxy_key,
    encode_auth_request_gcm, encode_forward_legacy, encode_forward_v2, encode_post_auth_frame,
};

const TEST_KEY: [u8; 16] = *b"0123456789abcdef";
const TEST_IV: [u8; 16] = *b"fedcba9876543210";

#[test]
fn proxy_endpoint_key_uses_first_sixteen_bytes_or_md5() {
    assert_eq!(derive_proxy_key("125.39.94.106:4013"), *b"125.39.94.106:40");
    assert_eq!(
        derive_proxy_key("1.2.3.4:80"),
        [
            0xee, 0x06, 0xc7, 0xfd, 0x69, 0x0d, 0x41, 0x2e, 0xc8, 0x89, 0x42, 0xd6, 0xef, 0x80,
            0x02, 0xba,
        ]
    );
}

#[test]
fn legacy_forward_encoder_matches_direct_p2p_payload_layout() {
    let inner = ipv4_packet();
    let payload = encode_forward_legacy(0x0102_0304, &inner).expect("legacy forward");
    assert_eq!(&payload[..5], &[1, 1, 2, 3, 4]);
    assert_eq!(&payload[5..], inner);
    let decoded = decode_forward_payload(&payload).expect("decode legacy");
    assert_eq!(decoded.version(), ForwardVersion::Legacy);
    assert_eq!(decoded.packet_id(), 0x0102_0304);
    assert_eq!(decoded.ip_packet(), inner);
}

#[test]
fn gcm_auth_request_matches_recovered_wire_shape_and_round_trips() {
    let request = AuthRequest::new(
        "AB12345",
        "fixture-password",
        "router-linux",
        "192.168.50.1",
    );

    let frame = encode_auth_request_gcm(&request, &TEST_KEY, &TEST_IV).expect("encode auth");

    let debug = format!("{request:?}");
    assert!(!debug.contains("fixture-password"));
    assert!(debug.contains("<redacted>"));

    assert_eq!(frame[0], MessageType::AuthRequest as u8);
    assert_eq!(
        u16::from_be_bytes([frame[1], frame[2]]) as usize,
        frame.len() - 3
    );
    assert_eq!(frame[3], EncryptionMethod::Aes128Gcm as u8);
    assert_eq!(frame[4], 16);
    assert_eq!(&frame[5..21], &TEST_IV);
    let expected_json = br#"{"room_id":"AB12345","password":"fixture-password","client_id":"router-linux","client_lan_ip":"192.168.50.1","encrypt_on":1}"#;
    assert_eq!(frame.len() - 21, expected_json.len() + 16);
    assert_eq!(
        format!("{:x}", Sha256::digest(&frame)),
        "4906a5b76117eb5354b8742b859093ee5b21d06d1026d0f1dfef45e4161b14a7"
    );
}

#[test]
fn gcm_auth_response_matches_independent_fixture() {
    let frame = from_hex(
        "01006b021066656463626139383736353433323130c7355037ca9ae23b1604486317d7ce6e22154f2469fb32a4066b282a4f49322077bb823d377d18277f93a4d4a24ba750f0c45d25854370acedd31c8f5169d4a7db1ea55a8c13907b7d02b19dbfc430639cef2763311abcb49c",
    );

    let response = decode_auth_response(&frame, &TEST_KEY).expect("GCM response");

    assert_eq!(response.result(), 0);
    assert_eq!(response.session_id_for_transport(), 123456);
    assert_eq!(response.xor_key_for_transport(), Some(b'K'));
}

#[test]
fn ecb_auth_response_matches_independent_fixture() {
    let frame = from_hex(
        "010051016858bc74c49a94be4dade7ca7047af3ef4a32146da8c4a3dd325f95e364d9340fe383ef6b3560b1af813104e94ff9d9771e97d67c851047be5ee0c442bd7cb8a920fba46531b46e9762d548bc6352341",
    );

    let response = decode_auth_response(&frame, &TEST_KEY).expect("ECB response");

    assert_eq!(response.result(), 0);
    assert_eq!(response.session_id_for_transport(), 654321);
    assert_eq!(response.xor_key_for_transport(), Some(b'Q'));
}

#[test]
fn plaintext_auth_response_parses_and_never_debugs_session_material() {
    let json = br#"{"result":0,"session_id":123456,"encrypt_method":"XOR","encrypt_key":"K"}"#;
    let mut frame = vec![MessageType::AuthResponse as u8];
    frame.extend_from_slice(&u16::try_from(json.len() + 1).unwrap().to_be_bytes());
    frame.push(EncryptionMethod::Plaintext as u8);
    frame.extend_from_slice(json);

    let response = decode_auth_response(&frame, &TEST_KEY).expect("valid response");

    assert_eq!(response.result(), 0);
    assert_eq!(response.session_id_for_transport(), 123456);
    assert_eq!(response.xor_key_for_transport(), Some(b'K'));
    let debug = format!("{response:?}");
    assert!(!debug.contains("123456"));
    assert!(!debug.contains('K'));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn rejected_auth_response_does_not_create_session_material() {
    let json = br#"{"result":7,"session_id":0,"encrypt_method":"","encrypt_key":""}"#;
    let mut frame = vec![MessageType::AuthResponse as u8];
    frame.extend_from_slice(&u16::try_from(json.len() + 1).unwrap().to_be_bytes());
    frame.push(EncryptionMethod::Plaintext as u8);
    frame.extend_from_slice(json);

    let response = decode_auth_response(&frame, &TEST_KEY).expect("parse rejection");

    assert_eq!(response.result(), 7);
    assert_eq!(response.xor_key_for_transport(), None);
}

#[test]
fn post_auth_frames_apply_single_byte_xor_to_payload_only() {
    let payload = b"packet-body";
    let encoded = encode_post_auth_frame(MessageType::Forward, payload, Some(0x5a))
        .expect("encode post-auth frame");

    assert_eq!(encoded[0], MessageType::Forward as u8);
    assert_eq!(&encoded[1..3], &(payload.len() as u16).to_be_bytes());
    assert_eq!(encoded[3], payload[0] ^ 0x5a);

    let decoded = decode_post_auth_frame(&encoded, Some(0x5a)).expect("decode post-auth frame");
    assert_eq!(decoded.message_type(), MessageType::Forward);
    assert_eq!(decoded.payload(), payload);
}

#[test]
fn forward_v2_ipv4_header_matches_windows_layout() {
    let inner = ipv4_packet();
    let packet_id = 0x0102_0304;
    let transport = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 4003);

    let payload = encode_forward_v2(packet_id, transport, &inner).expect("encode forward payload");

    assert_eq!(payload[0], 2);
    assert_eq!(&payload[1..5], &packet_id.to_be_bytes());
    assert_eq!(payload[5], 1);
    assert_eq!(&payload[6..10], &[203, 0, 113, 8]);
    assert_eq!(&payload[10..12], &4003_u16.to_be_bytes());
    assert_eq!(&payload[12..], &inner);

    let decoded = decode_forward_payload(&payload).expect("decode forward payload");
    assert_eq!(decoded.version(), ForwardVersion::Addressed);
    assert_eq!(decoded.packet_id(), packet_id);
    assert_eq!(decoded.transport_address(), Some(transport));
    assert_eq!(decoded.ip_packet(), inner);
}

#[test]
fn forward_v2_ipv6_transport_header_uses_twenty_four_bytes() {
    let inner = ipv4_packet();
    let packet_id = 0xa0b0_c0d0;
    let transport = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
        4013,
    );

    let payload = encode_forward_v2(packet_id, transport, &inner).expect("encode IPv6 transport");
    assert_eq!(payload.len(), 24 + inner.len());
    assert_eq!(payload[5], 4);

    let decoded = decode_forward_payload(&payload).expect("decode IPv6 transport");
    assert_eq!(decoded.transport_address(), Some(transport));
    assert_eq!(decoded.ip_packet(), inner);
}

#[test]
fn legacy_forward_header_and_malformed_inner_packets_are_bounded() {
    let inner = ipv4_packet();
    let mut legacy = vec![1, 172, 19, 163, 3];
    legacy.extend_from_slice(&inner);

    let decoded = decode_forward_payload(&legacy).expect("decode legacy forward payload");
    assert_eq!(decoded.version(), ForwardVersion::Legacy);
    assert_eq!(decoded.packet_id(), 0xac13_a303);
    assert_eq!(decoded.transport_address(), None);
    assert_eq!(decoded.ip_packet(), inner);

    assert!(matches!(
        decode_forward_payload(&[2, 172, 19, 163, 3, 9]),
        Err(ProtocolError::UnsupportedForwardAddressType(9))
    ));
    assert!(matches!(
        decode_forward_payload(&[2, 172, 19, 163, 3, 1, 127, 0, 0, 1, 0, 80]),
        Err(ProtocolError::InnerPacketTooShort { .. })
    ));
}

#[test]
fn malformed_or_unsupported_frames_fail_closed() {
    assert!(matches!(
        decode_auth_response(&[1, 0, 2, 9, b'{'], &TEST_KEY),
        Err(ProtocolError::UnsupportedEncryptionMethod(9))
    ));
    assert!(matches!(
        decode_post_auth_frame(&[64, 0, 2, 0], None),
        Err(ProtocolError::LengthMismatch { .. })
    ));
    assert!(matches!(
        decode_post_auth_frame(&[99, 0, 0], None),
        Err(ProtocolError::UnsupportedMessageType(99))
    ));
}

#[test]
fn auth_response_requires_the_first_server_packet_type() {
    let mut frame = vec![MessageType::Keepalive as u8, 0, 3, 0, b'{', b'}'];
    let error = decode_auth_response(&frame, &TEST_KEY).expect_err("wrong first packet type");
    assert!(matches!(
        error,
        ProtocolError::UnexpectedMessageType {
            expected: MessageType::AuthResponse,
            actual: MessageType::Keepalive,
        }
    ));

    frame[0] = MessageType::AuthResponse as u8;
    let parsed = decode_auth_response(&frame, &TEST_KEY);
    assert!(matches!(parsed, Err(ProtocolError::InvalidAuthJson(_))));
}

fn _assert_auth_response_is_send_sync(_: &AuthResponse) {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AuthResponse>();
}

fn from_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

fn ipv4_packet() -> Vec<u8> {
    vec![
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 172, 19, 163, 2, 172, 19, 163, 3,
    ]
}
