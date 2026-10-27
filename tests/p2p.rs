use std::net::{Ipv4Addr, SocketAddr};

use uu_linux_client::p2p::{
    EndpointGeo, P2pEndpoint, decode_address_info_packet, decode_data_datagram, decode_echo,
    decode_wan_discovery_response, encode_address_info_packet, encode_data_datagram, encode_echo,
    encode_echo_back, encode_wan_discovery_request,
};

fn inner_ipv4() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xac, 0x13, 0xa3,
        0x02, 0xac, 0x13, 0xa3, 0x03,
    ]
}

#[test]
fn binary_address_info_matches_recovered_official_wire_layout() {
    let endpoint = P2pEndpoint::new(
        "192.0.2.10:45000".parse::<SocketAddr>().unwrap(),
        EndpointGeo::China,
    );

    let packet = encode_address_info_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        0x40,
        0x0102_0304,
        &[endpoint],
    )
    .expect("address info");

    let expected = vec![
        0x45, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x40, 0xfd, 0x00, 0x00, 0xac, 0x13, 0xa3,
        0x02, 0xff, 0xff, 0xff, 0xff, 0xa1, 0x40, 0x01, 0x01, 0x02, 0x03, 0x04, 0x04, 0xaf, 0xc8,
        0xc0, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x67, 0x01, 0x01,
    ];
    assert_eq!(packet, expected);

    let decoded = decode_address_info_packet(&expected).expect("decode address info");
    assert_eq!(decoded.source(), Ipv4Addr::new(172, 19, 163, 2));
    assert_eq!(decoded.xor_key(), 0x40);
    assert_eq!(decoded.instance_id(), 0x0102_0304);
    assert_eq!(decoded.endpoints(), &[endpoint]);
}

#[test]
fn direct_data_datagram_wraps_legacy_forward_payload_and_uses_receiver_xor_key() {
    let mut forward = vec![0x01, 0x00, 0x00, 0x00, 0x65];
    forward.extend_from_slice(&inner_ipv4());

    let datagram =
        encode_data_datagram(0x40, 0x0102_0304, 0x4f, &forward).expect("encode direct data");

    let expected = vec![
        0x50, 0x50, 0x49, 0x21, 0x02, 0x0f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4e, 0x4f, 0x4f, 0x4f, 0x2a,
        0x0a, 0x4f, 0x4f, 0x5b, 0x4f, 0x4f, 0x4f, 0x4f, 0x0f, 0x4e, 0x4f, 0x4f, 0xe3, 0x5c, 0xec,
        0x4d, 0xe3, 0x5c, 0xec, 0x4c,
    ];
    assert_eq!(datagram, expected);

    let decoded = decode_data_datagram(&expected, 0x4f).expect("decode direct data");
    assert_eq!(decoded.sender_xor_key(), 0x40);
    assert_eq!(decoded.sender_instance_id(), 0x0102_0304);
    assert_eq!(decoded.forward_payload(), forward);
}

#[test]
fn echo_and_echo_back_match_twenty_one_byte_official_layout() {
    let echo = encode_echo(
        0x0102_0304_0506_0708,
        0x0a0b_0c0d,
        Ipv4Addr::new(192, 0, 2, 10),
    );
    let expected_echo = vec![
        0x50, 0x50, 0x49, 0x21, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c,
        0x0b, 0x0a, 0xc0, 0x00, 0x02, 0x0a,
    ];
    assert_eq!(echo, expected_echo);

    let echo_back =
        encode_echo_back(&expected_echo, Ipv4Addr::new(192, 0, 2, 20)).expect("echo back");
    let expected_back = vec![
        0x50, 0x50, 0x49, 0x21, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c,
        0x0b, 0x0a, 0xc0, 0x00, 0x02, 0x14,
    ];
    assert_eq!(echo_back, expected_back);

    let decoded = decode_echo(&expected_back).expect("decode echo back");
    assert!(decoded.is_echo_back());
    assert_eq!(decoded.timestamp_millis(), 0x0102_0304_0506_0708);
    assert_eq!(decoded.nonce(), 0x0a0b_0c0d);
    assert_eq!(decoded.client_ip(), Ipv4Addr::new(192, 0, 2, 20));
}

#[test]
fn malformed_or_wrongly_keyed_p2p_packets_fail_closed() {
    assert!(decode_address_info_packet(&[0x45; 20]).is_err());
    assert!(encode_data_datagram(0, 1, 0x4f, &[1, 0, 0, 0, 1]).is_err());
    assert!(decode_data_datagram(b"PPI!\x02short", 0x4f).is_err());
    assert!(encode_echo_back(b"not-an-echo", Ipv4Addr::LOCALHOST).is_err());
}

#[test]
fn wan_discovery_matches_recovered_official_udp_exchange() {
    let session_id = 12_370_393;
    let xor_key = b'n';

    assert_eq!(
        encode_wan_discovery_request(session_id, xor_key).expect("discovery request"),
        vec![0x00, 0x41, 0x00, 0xbc, 0xc1, 0xd9, 0x15, 0x13]
    );

    let captured_response = vec![
        0x00, 0x41, 0x00, 0xbc, 0xc1, 0xd9, 0x15, 0x4c, 0x07, 0x1d, 0x31, 0x01, 0x18, 0x0b, 0x1c,
        0x1d, 0x0b, 0x0f, 0x4c, 0x54, 0x08, 0x0f, 0x02, 0x1d, 0x0b, 0x42, 0x4c, 0x19, 0x0f, 0x00,
        0x31, 0x0f, 0x0a, 0x0a, 0x1c, 0x4c, 0x54, 0x4c, 0x5c, 0x5c, 0x5c, 0x40, 0x5f, 0x5c, 0x56,
        0x40, 0x5f, 0x56, 0x5b, 0x40, 0x5b, 0x5b, 0x54, 0x5c, 0x5f, 0x5a, 0x5b, 0x58, 0x4c, 0x13,
        0x64,
    ];
    let discovered = decode_wan_discovery_response(&captured_response, session_id, xor_key)
        .expect("WAN endpoint");

    assert_eq!(
        discovered.endpoint(),
        "222.128.185.55:21456".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(discovered.geo(), EndpointGeo::China);
}
