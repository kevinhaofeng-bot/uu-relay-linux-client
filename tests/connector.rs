use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

use uu_linux_client::bootstrap::JoinBootstrap;
use uu_linux_client::config::ClientConfig;
use uu_linux_client::runtime::{ConnectorError, RecoveredTcpConnector, RoomConnector};
use uu_linux_client::session::SessionSettings;

#[test]
fn recovered_connector_authenticates_and_retains_the_live_session() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture endpoint");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture client");
        let request = read_frame(&mut stream);
        assert_eq!(request[0], 0, "connector must send authentication first");

        let response =
            br#"{"result":0,"session_id":123456,"encrypt_method":"XOR","encrypt_key":"K"}"#;
        let mut frame = vec![1];
        frame.extend_from_slice(&u16::try_from(response.len() + 1).unwrap().to_be_bytes());
        frame.push(0);
        frame.extend_from_slice(response);
        stream.write_all(&frame).expect("write auth response");

        let keepalive = read_frame(&mut stream);
        assert_eq!(keepalive[0], 2);
        assert_eq!(keepalive[3] ^ b'K', b'{');
        assert_eq!(keepalive[4] ^ b'K', b'}');
    });
    let bootstrap = bootstrap(endpoint.port(), "AB12345", "172.19.163.2");
    let mut connector = RecoveredTcpConnector::new(bootstrap, settings());

    let acknowledgement = connector.join(&config("AB12345", "172.19.163.2"));

    let acknowledgement = acknowledgement.expect("authenticated connector");
    assert_eq!(acknowledgement.room_id(), "AB12345");
    assert_eq!(
        acknowledgement.assigned_address().to_string(),
        "172.19.163.2"
    );
    assert!(connector.has_session());
    connector
        .session_mut()
        .expect("retained session")
        .send_keepalive()
        .expect("keepalive on retained session");
    assert!(matches!(
        connector.join(&config("AB12345", "172.19.163.2")),
        Err(ConnectorError::AlreadyJoined)
    ));
    server.join().expect("fixture server finished");
    connector.disconnect();
    assert!(!connector.has_session());
}

#[test]
fn configuration_mismatch_is_rejected_before_network_access() {
    for (room_id, overlay_address, expected_field) in [
        ("ZZ99999", "172.19.163.2", "room_id"),
        ("AB12345", "172.19.163.9", "overlay_address"),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
        let endpoint = listener.local_addr().expect("fixture endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let bootstrap = bootstrap(endpoint.port(), "AB12345", "172.19.163.2");
        let mut connector = RecoveredTcpConnector::new(bootstrap, settings());

        let result = connector.join(&config(room_id, overlay_address));

        assert!(matches!(
            result,
            Err(ConnectorError::ConfigurationMismatch(field)) if field == expected_field
        ));
        assert!(!connector.has_session());
        assert_eq!(
            listener.accept().expect_err("must not connect").kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn a_connector_cannot_join_twice_or_hide_authentication_rejection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture endpoint");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture client");
        let _request = read_frame(&mut stream);
        let response = br#"{"result":7,"session_id":0,"encrypt_method":"","encrypt_key":""}"#;
        let mut frame = vec![1];
        frame.extend_from_slice(&u16::try_from(response.len() + 1).unwrap().to_be_bytes());
        frame.push(0);
        frame.extend_from_slice(response);
        stream.write_all(&frame).expect("write auth rejection");
    });
    let bootstrap = bootstrap(endpoint.port(), "AB12345", "172.19.163.2");
    let mut connector = RecoveredTcpConnector::new(bootstrap, settings());

    let result = connector.join(&config("AB12345", "172.19.163.2"));

    assert!(matches!(result, Err(ConnectorError::Session(_))));
    assert!(!connector.has_session());
    server.join().expect("fixture server finished");
}

fn bootstrap(port: u16, room_id: &str, client_lan_ip: &str) -> JoinBootstrap {
    let input = format!(
        r#"{{
          "action":"vlan_join_room",
          "data":{{"server_ip":"127.0.0.1","server_port":{port},"user_id":"fixture-user",
          "client_lan_ip":"{client_lan_ip}","client_lan_net":"172.19.163.0/24",
          "room_id":"{room_id}","password":"fixture-password","acc":"fixture-acc"}}
        }}"#
    );
    JoinBootstrap::parse_bridge_request(input.as_bytes(), room_id).expect("valid fixture bootstrap")
}

fn config(room_id: &str, overlay_address: &str) -> ClientConfig {
    ClientConfig::from_json(&format!(
        r#"{{
          "room_id":"{room_id}",
          "client_id":"router-linux",
          "overlay_address":"{overlay_address}",
          "session_token":"test-only-token"
        }}"#
    ))
    .expect("valid fixture config")
}

fn settings() -> SessionSettings {
    SessionSettings::new(Duration::from_secs(1), Duration::from_secs(1))
}

fn read_frame(stream: &mut impl Read) -> Vec<u8> {
    let mut header = [0_u8; 3];
    stream.read_exact(&mut header).expect("read fixture header");
    let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).expect("read fixture body");
    let mut frame = header.to_vec();
    frame.extend(body);
    frame
}
