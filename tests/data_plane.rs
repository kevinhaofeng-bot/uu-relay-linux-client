use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use uu_linux_client::bootstrap::RoomMemberTable;
use uu_linux_client::data_plane::{DataPlaneError, InboundFilter, OutboundRouter, ReplayDecision};
use uu_linux_client::protocol::encode_forward_v2;

fn members() -> RoomMemberTable {
    RoomMemberTable::parse_bridge_request(
        br#"{
          "action":"update_member_info",
          "data":{"member_info":[
            {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014},
            {"is_online":true,"client_lan_ip":"172.19.163.4","server_ip":"2001:db8::4","server_port":4015},
            {"is_online":false,"client_lan_ip":"172.19.163.5","server_ip":"203.0.113.11","server_port":4016}
          ]}
        }"#,
    )
    .expect("member fixture")
}

fn replacement_members() -> RoomMemberTable {
    RoomMemberTable::parse_bridge_request(
        br#"{
          "action":"update_member_info",
          "data":{"member_info":[
            {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.19","server_port":4114},
            {"is_online":true,"client_lan_ip":"172.19.163.6","server_ip":"203.0.113.12","server_port":4017}
          ]}
        }"#,
    )
    .expect("replacement member fixture")
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet
}

#[test]
fn unicast_routes_to_exact_member_and_uses_per_member_sequence() {
    let mut router = OutboundRouter::new(
        Ipv4Addr::new(172, 19, 163, 2),
        "172.19.163.0/24",
        &members(),
    )
    .expect("router");
    let packet = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 3),
    );

    let first = router.route(&packet).expect("first route");
    let second = router.route(&packet).expect("second route");

    assert_eq!(first.len(), 1);
    assert_eq!(first[0].packet_id(), 1);
    assert_eq!(second[0].packet_id(), 2);
    assert_eq!(
        first[0].transport_address(),
        "203.0.113.9:4014".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(first[0].ip_packet(), packet);
}

#[test]
fn broadcast_and_multicast_fan_out_with_one_shared_sequence() {
    let mut router = OutboundRouter::new(
        Ipv4Addr::new(172, 19, 163, 2),
        "172.19.163.0/24",
        &members(),
    )
    .expect("router");

    for destination in [
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(172, 19, 163, 255),
        Ipv4Addr::new(239, 255, 255, 250),
    ] {
        let packet = ipv4_packet(Ipv4Addr::new(172, 19, 163, 2), destination);
        let routes = router.route(&packet).expect("fan out");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].packet_id(), routes[1].packet_id());
    }

    let unicast_packet = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 4),
    );
    let next_unicast = router.route(&unicast_packet).expect("unicast after fanout");
    assert_eq!(next_unicast[0].packet_id(), 1);
}

#[test]
fn spoofed_source_unknown_destination_and_malformed_ipv4_fail_closed() {
    let mut router = OutboundRouter::new(
        Ipv4Addr::new(172, 19, 163, 2),
        "172.19.163.0/24",
        &members(),
    )
    .expect("router");

    assert!(matches!(
        router.route(&ipv4_packet(
            Ipv4Addr::new(172, 19, 163, 99),
            Ipv4Addr::new(172, 19, 163, 3),
        )),
        Err(DataPlaneError::UnexpectedSource(_))
    ));
    assert!(matches!(
        router.route(&ipv4_packet(
            Ipv4Addr::new(172, 19, 163, 2),
            Ipv4Addr::new(172, 19, 163, 99),
        )),
        Err(DataPlaneError::UnmappedDestination(_))
    ));
    assert!(matches!(
        router.route(&[0x45; 19]),
        Err(DataPlaneError::MalformedIpv4(_))
    ));
}

#[test]
fn inbound_requires_known_source_and_drops_duplicate_packet_ids() {
    let table = members();
    let mut inbound = InboundFilter::new(&table);
    let inner = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 3),
        Ipv4Addr::new(172, 19, 163, 2),
    );
    let payload = encode_forward_v2(
        44,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)), 4900),
        &inner,
    )
    .expect("payload");

    let accepted = inbound.inspect(&payload).expect("known member");
    assert_eq!(accepted.decision(), ReplayDecision::Accepted);
    assert_eq!(accepted.ip_packet(), inner);

    let duplicate = inbound.inspect(&payload).expect("duplicate is classified");
    assert_eq!(duplicate.decision(), ReplayDecision::Duplicate);

    let unknown_inner = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 99),
        Ipv4Addr::new(172, 19, 163, 2),
    );
    let unknown = encode_forward_v2(1, "203.0.113.20:4900".parse().unwrap(), &unknown_inner)
        .expect("unknown member payload");
    assert!(matches!(
        inbound.inspect(&unknown),
        Err(DataPlaneError::UnknownMember(_))
    ));
}

#[test]
fn replay_window_matches_recovered_sixty_four_packet_behavior_and_wrap() {
    let table = members();
    let mut inbound = InboundFilter::new(&table);
    let source = Ipv4Addr::new(172, 19, 163, 3);
    let destination = Ipv4Addr::new(172, 19, 163, 2);
    let packet = ipv4_packet(source, destination);
    let endpoint = "203.0.113.20:4900".parse().unwrap();

    for id in [1, 64, 65, u32::MAX, 1] {
        let payload = encode_forward_v2(id, endpoint, &packet).expect("payload");
        assert_eq!(
            inbound.inspect(&payload).expect("window").decision(),
            ReplayDecision::Accepted
        );
    }
    let wrapped_duplicate = encode_forward_v2(1, endpoint, &packet).expect("duplicate payload");
    assert_eq!(
        inbound
            .inspect(&wrapped_duplicate)
            .expect("duplicate after wrap")
            .decision(),
        ReplayDecision::Duplicate
    );
}

#[test]
fn member_refresh_preserves_existing_sequences_and_removes_offline_members() {
    let mut router = OutboundRouter::new(
        Ipv4Addr::new(172, 19, 163, 2),
        "172.19.163.0/24",
        &members(),
    )
    .expect("router");
    let existing = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 3),
    );
    assert_eq!(router.route(&existing).unwrap()[0].packet_id(), 1);

    router.update_members(&replacement_members());

    let refreshed = router.route(&existing).expect("existing member remains");
    assert_eq!(refreshed[0].packet_id(), 2);
    assert_eq!(
        refreshed[0].transport_address(),
        "203.0.113.19:4114".parse().unwrap()
    );
    let new_member = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 6),
    );
    assert_eq!(router.route(&new_member).unwrap()[0].packet_id(), 1);
    let removed = ipv4_packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 4),
    );
    assert!(matches!(
        router.route(&removed),
        Err(DataPlaneError::UnmappedDestination(_))
    ));
}
