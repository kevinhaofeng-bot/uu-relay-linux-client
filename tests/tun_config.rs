use std::net::Ipv4Addr;

use uu_linux_client::tun::{TunError, linux_interface_commands, linux_member_route_commands};

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
