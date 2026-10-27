use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use aes::Aes128;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{AesGcm, Nonce, Tag};
use serde_json::Value;
use uu_linux_client::protocol::{AuthRequest, MessageType, derive_proxy_key};
use uu_linux_client::session::{SessionError, SessionSettings, TcpRoomSession};

type Aes128Gcm16 = AesGcm<Aes128, U16>;

#[test]
fn tcp_session_authenticates_then_exchanges_keepalive_and_forward_frames() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture endpoint");
    let server = thread::spawn(move || fixture_server(listener, endpoint));

    let request = AuthRequest::new(
        "AB12345",
        "fixture-password",
        "router-linux",
        "172.19.163.2",
    );
    let settings = SessionSettings::new(Duration::from_secs(1), Duration::from_secs(1));
    let session =
        TcpRoomSession::connect(endpoint, &request, settings).expect("authenticated session");

    assert!(!format!("{session:?}").contains("fixture-password"));
    assert_eq!(session.p2p_session_id(), Some(123_456));
    assert_eq!(session.remote_transport_address().unwrap(), endpoint);
    let (mut sender, mut receiver) = session.try_split().expect("split session I/O");
    assert!(!format!("{sender:?}{receiver:?}").contains('K'));
    sender.send_keepalive().expect("send keepalive");
    let frame = receiver.receive().expect("receive forward frame");
    assert_eq!(frame.message_type(), MessageType::Forward);
    assert_eq!(frame.payload(), b"fixture-forward");

    server.join().expect("fixture server finished");
}

#[test]
fn rejected_authentication_never_creates_a_session() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
    let endpoint = listener.local_addr().expect("fixture endpoint");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture client");
        let _request = read_frame(&mut stream);
        let response = br#"{"result":9,"session_id":0,"encrypt_method":"","encrypt_key":""}"#;
        let mut frame = vec![1];
        frame.extend_from_slice(&u16::try_from(response.len() + 1).unwrap().to_be_bytes());
        frame.push(0);
        frame.extend_from_slice(response);
        stream.write_all(&frame).expect("write rejection");
    });

    let request = AuthRequest::new("AB12345", "bad", "router-linux", "172.19.163.2");
    let result = TcpRoomSession::connect(
        endpoint,
        &request,
        SessionSettings::new(Duration::from_secs(1), Duration::from_secs(1)),
    );

    assert!(matches!(
        result,
        Err(SessionError::AuthenticationRejected(9))
    ));
    server.join().expect("fixture server finished");
}

#[test]
fn oversized_or_truncated_server_frames_fail_closed() {
    for declared_length in [16_385_u16, 40_u16] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture server");
        let endpoint = listener.local_addr().expect("fixture endpoint");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fixture client");
            let _request = read_frame(&mut stream);
            stream
                .write_all(&[1, (declared_length >> 8) as u8, declared_length as u8, 0])
                .expect("write malformed response");
        });

        let request = AuthRequest::new("AB12345", "bad", "router-linux", "172.19.163.2");
        let result = TcpRoomSession::connect(
            endpoint,
            &request,
            SessionSettings::new(Duration::from_secs(1), Duration::from_millis(150)),
        );

        assert!(matches!(
            result,
            Err(SessionError::FrameTooLarge { .. }) | Err(SessionError::Io(_))
        ));
        server.join().expect("fixture server finished");
    }
}

fn fixture_server(listener: TcpListener, endpoint: SocketAddr) {
    let (mut stream, _) = listener.accept().expect("accept fixture client");
    let request = read_frame(&mut stream);
    assert_eq!(request[0], 0);
    assert_eq!(request[3], 2);
    assert_eq!(request[4], 16);

    let key = derive_proxy_key(&endpoint.to_string());
    let iv = &request[5..21];
    let ciphertext_end = request.len() - 16;
    let mut plaintext = request[21..ciphertext_end].to_vec();
    let tag = Tag::<U16>::from_slice(&request[ciphertext_end..]);
    let cipher = Aes128Gcm16::new_from_slice(&key).expect("fixture key");
    cipher
        .decrypt_in_place_detached(Nonce::<U16>::from_slice(iv), b"", &mut plaintext, tag)
        .expect("decrypt client auth");
    let request_json: Value = serde_json::from_slice(&plaintext).expect("client auth JSON");
    assert_eq!(request_json["room_id"], "AB12345");
    assert_eq!(request_json["client_lan_ip"], "172.19.163.2");

    let response = br#"{"result":0,"session_id":123456,"encrypt_method":"XOR","encrypt_key":"K"}"#;
    let mut frame = vec![1];
    frame.extend_from_slice(&u16::try_from(response.len() + 1).unwrap().to_be_bytes());
    frame.push(0);
    frame.extend_from_slice(response);
    stream.write_all(&frame).expect("write auth response");

    let keepalive = read_frame(&mut stream);
    assert_eq!(keepalive[0], MessageType::Keepalive as u8);
    assert_eq!(keepalive[3] ^ b'K', b'{');
    assert_eq!(keepalive[4] ^ b'K', b'}');

    let payload = b"fixture-forward";
    let mut forward = vec![MessageType::Forward as u8];
    forward.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    forward.extend(payload.iter().map(|byte| byte ^ b'K'));
    stream.write_all(&forward).expect("write forward frame");
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
