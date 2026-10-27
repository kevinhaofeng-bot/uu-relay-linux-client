use std::net::{Ipv4Addr, SocketAddr};

use uu_linux_client::bootstrap::RoomMemberTable;
use uu_linux_client::p2p::{
    EndpointGeo, P2pEndpoint, PeerDirectory, decode_address_info_packet, encode_address_info_packet,
};

fn members() -> RoomMemberTable {
    RoomMemberTable::parse_bridge_request(
        br#"{"action":"update_member_info","data":{"member_info":[
          {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014}
        ]}}"#,
    )
    .expect("members")
}

#[test]
fn address_info_requires_echo_confirmation_before_direct_routing() {
    let peer = Ipv4Addr::new(172, 19, 163, 3);
    let relay = "203.0.113.9:4014".parse::<SocketAddr>().unwrap();
    let endpoint = "192.0.2.169:50713".parse::<SocketAddr>().unwrap();
    let packet = encode_address_info_packet(
        peer,
        0x4f,
        0x0102_0304,
        &[P2pEndpoint::new(endpoint, EndpointGeo::China)],
    )
    .unwrap();
    let info = decode_address_info_packet(&packet).unwrap();

    let mut directory = PeerDirectory::new(&members());
    directory.observe_address_info(&info).unwrap();
    assert!(directory.direct_target_for_relay(relay).is_none());
    assert!(!directory.observe_echo(peer, "192.0.2.169:9999".parse().unwrap()));
    assert!(directory.observe_echo(peer, endpoint));

    let target = directory
        .direct_target_for_relay(relay)
        .expect("confirmed direct route");
    assert_eq!(target.overlay_ip(), peer);
    assert_eq!(target.endpoint(), endpoint);
    assert_eq!(target.xor_key(), 0x4f);
    assert_eq!(target.instance_id(), 0x0102_0304);
}

#[test]
fn authenticated_direct_data_can_learn_a_known_peer_but_not_an_unknown_overlay_source() {
    let known = Ipv4Addr::new(172, 19, 163, 3);
    let unknown = Ipv4Addr::new(172, 19, 163, 99);
    let relay = "203.0.113.9:4014".parse::<SocketAddr>().unwrap();
    let endpoint = "192.0.2.169:50713".parse::<SocketAddr>().unwrap();
    let mut directory = PeerDirectory::new(&members());

    assert!(
        directory
            .observe_direct_data(unknown, 0x4f, 0x0102_0304, endpoint)
            .is_err()
    );
    directory
        .observe_direct_data(known, 0x4f, 0x0102_0304, endpoint)
        .unwrap();
    assert_eq!(
        directory.direct_target_for_relay(relay).unwrap().endpoint(),
        endpoint
    );
}

#[test]
fn member_refresh_removes_stale_direct_routes() {
    let known = Ipv4Addr::new(172, 19, 163, 3);
    let relay = "203.0.113.9:4014".parse::<SocketAddr>().unwrap();
    let endpoint = "192.0.2.169:50713".parse::<SocketAddr>().unwrap();
    let mut directory = PeerDirectory::new(&members());
    directory
        .observe_direct_data(known, 0x4f, 0x0102_0304, endpoint)
        .unwrap();

    let empty = RoomMemberTable::parse_bridge_request(
        br#"{"action":"update_member_info","data":{"member_info":[]}}"#,
    )
    .unwrap();
    directory.update_members(&empty);
    assert!(directory.direct_target_for_relay(relay).is_none());
}
