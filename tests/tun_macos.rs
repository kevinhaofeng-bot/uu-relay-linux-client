#![cfg(target_os = "macos")]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use uu_linux_client::tun::{MacOsTunBackend, TunBackend};

#[test]
#[ignore = "requires root to create a macOS utun interface"]
fn creates_and_closes_the_requested_utun_interface() {
    let interface = "utun63";
    let mut backend = MacOsTunBackend::new(interface).expect("valid utun name");
    let mut device = backend
        .create(IpAddr::V4(Ipv4Addr::new(172, 19, 163, 3)))
        .expect("create utun interface");

    let status = Command::new("/sbin/ifconfig")
        .arg(interface)
        .status()
        .expect("inspect utun interface");
    assert!(status.success(), "requested utun interface is absent");

    device.close().expect("close utun interface");
}
