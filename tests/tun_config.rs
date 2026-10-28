use std::net::Ipv4Addr;

use uu_linux_client::tun::{
    TunError, decode_macos_utun_packet, encode_macos_utun_packet, linux_interface_commands,
    linux_member_route_commands, macos_interface_commands, macos_member_route_commands,
    macos_utun_unit,
};

#[test]
fn linux_interface_commands_assign_address_then_raise_link() {
    let commands =
        linux_interface_commands("uu0", Ipv4Addr::new(172, 19, 163, 2), "172.19.163.0/24")
            .expect("valid interface plan");

    assert_eq!(
        commands,
        [
            vec!["address", "replace", "172.19.163.2/24", "dev", "uu0"],
            vec!["link", "set", "dev", "uu0", "up"],
        ]
    );
}

#[test]
fn invalid_or_mismatched_overlay_network_is_rejected_before_ip_command() {
    assert!(matches!(
        linux_interface_commands("uu0", Ipv4Addr::new(172, 19, 163, 2), "not-a-network"),
        Err(TunError::InvalidOverlayNetwork(_))
    ));
    assert!(matches!(
        linux_interface_commands("uu0", Ipv4Addr::new(172, 19, 164, 2), "172.19.163.0/24"),
        Err(TunError::AddressOutsideNetwork { .. })
    ));
}

#[test]
fn member_host_routes_override_a_conflicting_legacy_overlay_route() {
    let commands = linux_member_route_commands(
        "uu0",
        Ipv4Addr::new(172, 19, 163, 2),
        "172.19.163.0/24",
        &[
            Ipv4Addr::new(172, 19, 163, 3),
            Ipv4Addr::new(172, 19, 163, 4),
        ],
        &[
            Ipv4Addr::new(172, 19, 163, 4),
            Ipv4Addr::new(172, 19, 163, 5),
        ],
    )
    .expect("valid member route plan");

    assert_eq!(
        commands,
        [
            vec![
                "route",
                "replace",
                "172.19.163.5/32",
                "dev",
                "uu0",
                "src",
                "172.19.163.2",
            ],
            vec!["route", "del", "172.19.163.3/32", "dev", "uu0",],
        ]
    );
}

#[test]
fn member_host_routes_reject_addresses_outside_the_overlay() {
    assert!(matches!(
        linux_member_route_commands(
            "uu0",
            Ipv4Addr::new(172, 19, 163, 2),
            "172.19.163.0/24",
            &[],
            &[Ipv4Addr::new(192, 0, 2, 1)],
        ),
        Err(TunError::MemberOutsideNetwork { .. })
    ));
}

#[test]
fn macos_interface_commands_configure_point_to_point_ipv4() {
    let commands =
        macos_interface_commands("utun15", Ipv4Addr::new(172, 19, 163, 3), "172.19.163.0/24")
            .expect("valid macOS interface plan");

    assert_eq!(
        commands,
        [vec![
            "utun15",
            "inet",
            "172.19.163.3",
            "172.19.163.3",
            "netmask",
            "255.255.255.0",
            "up",
        ]]
    );
}

#[test]
fn macos_member_routes_use_interface_scoped_host_routes() {
    let commands = macos_member_route_commands(
        "utun15",
        Ipv4Addr::new(172, 19, 163, 3),
        "172.19.163.0/24",
        &[Ipv4Addr::new(172, 19, 163, 2)],
        &[
            Ipv4Addr::new(172, 19, 163, 2),
            Ipv4Addr::new(172, 19, 163, 4),
        ],
    )
    .expect("valid macOS route plan");

    assert_eq!(
        commands,
        [vec![
            "-n",
            "add",
            "-host",
            "172.19.163.4",
            "-interface",
            "utun15",
        ]]
    );

    let removals = macos_member_route_commands(
        "utun15",
        Ipv4Addr::new(172, 19, 163, 3),
        "172.19.163.0/24",
        &[Ipv4Addr::new(172, 19, 163, 2)],
        &[],
    )
    .expect("valid macOS route removal plan");
    assert_eq!(removals, [vec!["-n", "delete", "-host", "172.19.163.2"]]);
}

#[test]
fn macos_utun_framing_adds_and_removes_ipv4_address_family_header() {
    let packet = [0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0];
    let framed = encode_macos_utun_packet(&packet).expect("frame IPv4 packet");
    assert_eq!(&framed[..4], &[0, 0, 0, 2]);
    assert_eq!(&framed[4..], packet);

    let mut decoded = [0_u8; 32];
    let length = decode_macos_utun_packet(&framed, &mut decoded).expect("decode IPv4 frame");
    assert_eq!(length, packet.len());
    assert_eq!(&decoded[..length], packet);
}

#[test]
fn macos_utun_framing_rejects_non_ipv4_and_short_frames() {
    let mut output = [0_u8; 32];
    assert!(matches!(
        decode_macos_utun_packet(&[0, 0, 0, 30, 0x60], &mut output),
        Err(TunError::Operation(_))
    ));
    assert!(matches!(
        decode_macos_utun_packet(&[0, 0, 0], &mut output),
        Err(TunError::Operation(_))
    ));
}

#[test]
fn macos_utun_names_map_to_kernel_control_units() {
    assert_eq!(macos_utun_unit("utun0").expect("utun0"), 1);
    assert_eq!(macos_utun_unit("utun15").expect("utun15"), 16);
    assert!(matches!(
        macos_utun_unit("uu0"),
        Err(TunError::InvalidInterfaceName(_))
    ));
    assert!(matches!(
        macos_utun_unit("utun"),
        Err(TunError::InvalidInterfaceName(_))
    ));
}
