use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use uu_linux_client::bootstrap::{
    BootstrapError, JoinBootstrap, OfficialRoomJoin, RoomMemberTable,
};

#[test]
fn recovered_native_join_bridge_request_builds_secret_safe_auth_material() {
    let input = br#"{
      "action": "vlan_join_room",
      "data": {
        "server_ip": "203.0.113.8",
        "server_port": 4013,
        "user_id": "user-fixture",
        "client_lan_ip": "172.19.163.2",
        "client_lan_net": "172.19.163.0/24",
        "room_id": "AB12345",
        "password": "room-secret",
        "acc": "acc-secret",
        "vlan_wfp_firewall": false,
        "vlan_game_process_name": "",
        "vlan_process_block_ports": "",
        "vlan_prefer_wintun": true
      }
    }"#;

    let bootstrap =
        JoinBootstrap::parse_bridge_request(input, "AB12345").expect("valid native bridge request");

    assert_eq!(
        bootstrap.server_endpoint(),
        "203.0.113.8:4013".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(bootstrap.client_lan_ip(), Ipv4Addr::new(172, 19, 163, 2));
    assert_eq!(bootstrap.room_id(), "AB12345");
    let debug = format!("{bootstrap:?}");
    assert!(!debug.contains("room-secret"));
    assert!(!debug.contains("user-fixture"));
    assert!(!debug.contains("acc-secret"));
    assert_eq!(debug.matches("<redacted>").count(), 3);

    let auth = bootstrap.auth_request();
    let auth_debug = format!("{auth:?}");
    assert!(auth_debug.contains("AB12345"));
    assert!(auth_debug.contains("172.19.163.2"));
    assert!(!auth_debug.contains("room-secret"));
    assert!(!auth_debug.contains("user-fixture"));
}

#[test]
fn wrong_room_and_wrong_native_action_fail_closed() {
    let wrong_room = br#"{
      "action":"vlan_join_room",
      "data":{"server_ip":"203.0.113.8","server_port":4013,"user_id":"u",
      "client_lan_ip":"172.19.163.2","client_lan_net":"172.19.163.0/24",
      "room_id":"ZZ99999","password":"p","acc":"a"}
    }"#;
    assert!(matches!(
        JoinBootstrap::parse_bridge_request(wrong_room, "AB12345"),
        Err(BootstrapError::RoomMismatch { .. })
    ));

    let wrong_action = br#"{"action":"update_member_info","data":{}}"#;
    assert!(matches!(
        JoinBootstrap::parse_bridge_request(wrong_action, "AB12345"),
        Err(BootstrapError::InvalidAction { .. })
    ));
}

#[test]
fn official_http_join_response_builds_native_bootstrap_and_members() {
    let input = br#"{
      "code": 200,
      "data": {
        "room": {
          "room_id": "AB12345",
          "game_id": "fixture-game",
          "password": "room-secret",
          "wfp_firewall": false,
          "game_process_name": "",
          "prefer_wintun": true,
          "process_block_ports": "",
          "members": [
            {"is_self":true,"is_online":true,"user_id":"self-member",
             "client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4013},
            {"is_self":false,"is_online":true,"user_id":"peer-member",
             "client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014},
            {"is_self":false,"is_online":false,"user_id":"offline-member",
             "client_lan_ip":"172.19.163.4","server_ip":"203.0.113.10","server_port":4015}
          ]
        },
        "user": {"user_id":"account-user"},
        "app": {"client_lan_net":"172.19.163.0/24","acc":"acc-secret","client":"fixture"}
      }
    }"#;

    let joined = OfficialRoomJoin::parse_http_response(input, "AB12345")
        .expect("valid official join response");
    let bootstrap = joined.bootstrap();

    assert_eq!(
        bootstrap.server_endpoint(),
        "203.0.113.8:4013".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(bootstrap.client_lan_ip(), Ipv4Addr::new(172, 19, 163, 2));
    assert_eq!(joined.members().online().len(), 1);
    assert_eq!(
        joined.members().online()[0].client_lan_ip(),
        Ipv4Addr::new(172, 19, 163, 3)
    );
    let debug = format!("{joined:?}");
    assert!(!debug.contains("room-secret"));
    assert!(!debug.contains("account-user"));
    assert!(!debug.contains("acc-secret"));
}

#[test]
fn official_join_keeps_offline_self_bootstrap_for_online_transition() {
    let input = br#"{
      "code":200,
      "data":{
        "room":{"room_id":"AB12345","password":"p","members":[
          {"is_self":true,"is_online":false,"client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4013}
        ]},
        "user":{"user_id":123456789},
        "app":{"client_lan_net":"172.19.163.0/24","acc":"a"}
      }
    }"#;

    let joined = OfficialRoomJoin::parse_http_response(input, "AB12345")
        .expect("offline self still carries the native bootstrap");

    assert!(!joined.self_is_online());
    assert_eq!(
        joined.bootstrap().client_lan_ip(),
        Ipv4Addr::new(172, 19, 163, 2)
    );
}

#[test]
fn official_http_join_rejects_api_error_and_ambiguous_self_member() {
    let rejected = br#"{"code":10017,"data":null}"#;
    assert!(matches!(
        OfficialRoomJoin::parse_http_response(rejected, "AB12345"),
        Err(BootstrapError::ApiRejected(10017))
    ));

    let duplicate_self = br#"{
      "code":200,
      "data":{
        "room":{"room_id":"AB12345","password":"p","members":[
          {"is_self":true,"is_online":true,"client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4013},
          {"is_self":true,"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014}
        ]},
        "user":{"user_id":"u"},
        "app":{"client_lan_net":"172.19.163.0/24","acc":"a","client":"fixture"}
      }
    }"#;
    assert!(matches!(
        OfficialRoomJoin::parse_http_response(duplicate_self, "AB12345"),
        Err(BootstrapError::AmbiguousSelfMember(2))
    ));
}

#[test]
fn online_member_table_matches_recovered_update_shape() {
    let input = br#"{
      "action":"update_member_info",
      "data":{"member_info":[
        {"is_online":true,"client_lan_ip":"172.19.163.2","server_ip":"203.0.113.8","server_port":4003},
        {"is_online":false,"client_lan_ip":"172.19.163.9","server_ip":"203.0.113.9","server_port":4004},
        {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"2001:db8::3","server_port":4005}
      ]}
    }"#;

    let table = RoomMemberTable::parse_bridge_request(input).expect("valid member update");

    assert_eq!(table.online().len(), 2);
    assert_eq!(
        table.online()[0].client_lan_ip(),
        Ipv4Addr::new(172, 19, 163, 2)
    );
    assert_eq!(
        table.online()[0].transport_address(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 4003)
    );
    assert!(table.online()[1].transport_address().is_ipv6());
}

#[test]
fn invalid_or_duplicate_online_members_are_rejected() {
    let duplicate = br#"{
      "action":"update_member_info",
      "data":{"member_info":[
        {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.8","server_port":4003},
        {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4004}
      ]}
    }"#;
    assert!(matches!(
        RoomMemberTable::parse_bridge_request(duplicate),
        Err(BootstrapError::DuplicateMember(address))
            if address == Ipv4Addr::new(172, 19, 163, 3)
    ));

    let invalid = br#"{
      "action":"update_member_info",
      "data":{"member_info":[
        {"is_online":true,"client_lan_ip":"not-an-ip","server_ip":"203.0.113.8","server_port":4003}
      ]}
    }"#;
    assert!(matches!(
        RoomMemberTable::parse_bridge_request(invalid),
        Err(BootstrapError::InvalidField("client_lan_ip"))
    ));

    let zero_port = br#"{
      "action":"update_member_info",
      "data":{"member_info":[
        {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.8","server_port":0}
      ]}
    }"#;
    assert!(matches!(
        RoomMemberTable::parse_bridge_request(zero_port),
        Err(BootstrapError::InvalidField("server_port"))
    ));
}

#[test]
fn zero_port_join_endpoint_is_rejected() {
    let input = br#"{
      "action":"vlan_join_room",
      "data":{"server_ip":"203.0.113.8","server_port":0,"user_id":"u",
      "client_lan_ip":"172.19.163.2","client_lan_net":"172.19.163.0/24",
      "room_id":"AB12345","password":"p","acc":"a"}
    }"#;

    assert!(matches!(
        JoinBootstrap::parse_bridge_request(input, "AB12345"),
        Err(BootstrapError::InvalidField("server_port"))
    ));
}
