use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aes::Aes128;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{AesGcm, Nonce, Tag};
use uu_linux_client::bootstrap::RoomMemberTable;
use uu_linux_client::p2p::{
    EndpointGeo, P2pEndpoint, decode_address_info_packet, decode_data_datagram, decode_echo,
    decode_wan_discovery_response, encode_address_info_packet, encode_echo_back,
};
use uu_linux_client::protocol::{
    AuthRequest, ForwardVersion, MessageType, decode_forward_payload, derive_proxy_key,
    encode_forward_v2, encode_post_auth_frame,
};
use uu_linux_client::session::{SessionSettings, TcpRoomSession};
use uu_linux_client::tun::{TunDevice, TunError};
use uu_linux_client::workers::{BridgeWorkers, WorkerSettings};

type Aes128Gcm16 = AesGcm<Aes128, U16>;

#[derive(Default)]
struct TunState {
    outbound: VecDeque<Vec<u8>>,
    injected: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct FakeTun {
    state: Arc<Mutex<TunState>>,
}

impl TunDevice for FakeTun {
    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, TunError> {
        let Some(packet) = self.state.lock().unwrap().outbound.pop_front() else {
            return Ok(None);
        };
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        self.state.lock().unwrap().injected.push(packet.to_vec());
        Ok(())
    }

    fn try_clone_device(&self) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(self.clone()))
    }

    fn close(&mut self) -> Result<(), TunError> {
        Ok(())
    }
}

fn members() -> RoomMemberTable {
    RoomMemberTable::parse_bridge_request(
        br#"{"action":"update_member_info","data":{"member_info":[
          {"is_online":true,"client_lan_ip":"172.19.163.3","server_ip":"203.0.113.9","server_port":4014}
        ]}}"#,
    )
    .expect("members")
}

fn packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
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
fn workers_bridge_tun_and_authenticated_tcp_in_both_directions() {
    let local = Ipv4Addr::new(172, 19, 163, 2);
    let peer = Ipv4Addr::new(172, 19, 163, 3);
    let outbound = packet(local, peer);
    let inbound = packet(peer, local);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    let endpoint = listener.local_addr().unwrap();
    let expected_outbound = outbound.clone();
    let mut kernel_ipv6_probe = vec![0_u8; 40];
    kernel_ipv6_probe[0] = 0x60;
    let sent_inbound = inbound.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fixture accept");
        authenticate_fixture(&mut stream, endpoint);

        let address_frame = read_frame(&mut stream);
        assert_eq!(address_frame[0], MessageType::Forward as u8);
        let decoded_address: Vec<u8> = address_frame[3..].iter().map(|byte| byte ^ b'K').collect();
        let address_forward =
            decode_forward_payload(&decoded_address).expect("client address forward");
        assert_eq!(
            decode_address_info_packet(address_forward.ip_packet())
                .expect("client address info")
                .source(),
            local
        );

        let client_frame = read_frame(&mut stream);
        assert_eq!(client_frame[0], MessageType::Forward as u8);
        let decoded_client: Vec<u8> = client_frame[3..].iter().map(|byte| byte ^ b'K').collect();
        assert_eq!(
            decode_forward_payload(&decoded_client)
                .expect("client forward")
                .ip_packet(),
            expected_outbound
        );

        let payload = encode_forward_v2(1, endpoint, &sent_inbound).expect("server forward");
        let frame = encode_post_auth_frame(MessageType::Forward, &payload, Some(b'K'))
            .expect("server frame");
        stream.write_all(&frame).expect("send server frame");
        thread::sleep(Duration::from_millis(150));
    });

    let request = AuthRequest::new("AB12345", "fixture", "router-linux", local.to_string());
    let session = TcpRoomSession::connect(
        endpoint,
        &request,
        SessionSettings::new(Duration::from_secs(1), Duration::from_millis(50)),
    )
    .expect("session");
    let state = Arc::new(Mutex::new(TunState {
        outbound: VecDeque::from([kernel_ipv6_probe, outbound]),
        injected: Vec::new(),
    }));
    let tun = FakeTun {
        state: state.clone(),
    };
    let workers = BridgeWorkers::start(
        &tun,
        &session,
        local,
        "172.19.163.0/24",
        &members(),
        WorkerSettings::new(Duration::from_millis(1), Duration::from_secs(30)),
    )
    .expect("start bridge workers");

    let deadline = Instant::now() + Duration::from_secs(1);
    while state.lock().unwrap().injected.is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    workers.shutdown().expect("worker shutdown");
    server.join().expect("fixture server");

    assert_eq!(state.lock().unwrap().injected, vec![inbound]);
}

#[test]
fn workers_drop_rejected_tun_packets_and_keep_forwarding() {
    let local = Ipv4Addr::new(172, 19, 163, 2);
    let peer = Ipv4Addr::new(172, 19, 163, 3);
    let valid = packet(local, peer);
    let expected_valid = valid.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    let endpoint = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fixture accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        authenticate_fixture(&mut stream, endpoint);

        let address_frame = read_frame(&mut stream);
        assert_eq!(address_frame[0], MessageType::Forward as u8);

        let client_frame = read_frame(&mut stream);
        let decoded_client: Vec<u8> = client_frame[3..].iter().map(|byte| byte ^ b'K').collect();
        assert_eq!(
            decode_forward_payload(&decoded_client)
                .expect("valid client forward")
                .ip_packet(),
            expected_valid
        );
    });

    let request = AuthRequest::new("AB12345", "fixture", "router-linux", local.to_string());
    let session = TcpRoomSession::connect(
        endpoint,
        &request,
        SessionSettings::new(Duration::from_secs(1), Duration::from_millis(50)),
    )
    .expect("session");
    let state = Arc::new(Mutex::new(TunState {
        outbound: VecDeque::from([
            packet(Ipv4Addr::new(192, 168, 1, 4), peer),
            packet(local, Ipv4Addr::new(172, 19, 163, 4)),
            valid,
        ]),
        injected: Vec::new(),
    }));
    let tun = FakeTun { state };
    let workers = BridgeWorkers::start(
        &tun,
        &session,
        local,
        "172.19.163.0/24",
        &members(),
        WorkerSettings::new(Duration::from_millis(1), Duration::from_secs(30)),
    )
    .expect("start bridge workers");

    server.join().expect("fixture server");
    workers.shutdown().expect("worker shutdown");
}

#[test]
fn workers_drop_rejected_inbound_packets_and_keep_injecting() {
    let local = Ipv4Addr::new(172, 19, 163, 2);
    let peer = Ipv4Addr::new(172, 19, 163, 3);
    let valid = packet(peer, local);
    let expected_valid = valid.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    let endpoint = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fixture accept");
        authenticate_fixture(&mut stream, endpoint);

        let address_frame = read_frame(&mut stream);
        assert_eq!(address_frame[0], MessageType::Forward as u8);

        for (packet_id, ip_packet) in [
            (1, packet(Ipv4Addr::new(172, 19, 163, 4), local)),
            (2, expected_valid),
        ] {
            let payload = encode_forward_v2(packet_id, endpoint, &ip_packet).unwrap();
            let frame = encode_post_auth_frame(MessageType::Forward, &payload, Some(b'K')).unwrap();
            stream.write_all(&frame).expect("server forward");
        }
        thread::sleep(Duration::from_millis(150));
    });

    let request = AuthRequest::new("AB12345", "fixture", "router-linux", local.to_string());
    let session = TcpRoomSession::connect(
        endpoint,
        &request,
        SessionSettings::new(Duration::from_secs(1), Duration::from_millis(50)),
    )
    .expect("session");
    let state = Arc::new(Mutex::new(TunState::default()));
    let tun = FakeTun {
        state: state.clone(),
    };
    let workers = BridgeWorkers::start(
        &tun,
        &session,
        local,
        "172.19.163.0/24",
        &members(),
        WorkerSettings::new(Duration::from_millis(1), Duration::from_secs(30)),
    )
    .expect("start bridge workers");

    let deadline = Instant::now() + Duration::from_secs(1);
    while state.lock().unwrap().injected.is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    workers.shutdown().expect("worker shutdown");
    server.join().expect("fixture server");

    assert_eq!(state.lock().unwrap().injected, vec![valid]);
}

#[test]
fn workers_negotiate_p2p_and_move_user_data_over_direct_udp() {
    let local = Ipv4Addr::new(172, 19, 163, 2);
    let peer = Ipv4Addr::new(172, 19, 163, 3);
    let outbound = packet(local, peer);
    let expected_outbound = outbound.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("fixture listener");
    let tcp_endpoint = listener.local_addr().unwrap();
    let discovery_udp = UdpSocket::bind(tcp_endpoint).expect("fixture discovery UDP");
    discovery_udp
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let peer_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("peer UDP");
    peer_udp
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let peer_endpoint = peer_udp.local_addr().unwrap();
    let state = Arc::new(Mutex::new(TunState::default()));
    let server_state = state.clone();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("fixture accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        authenticate_fixture(&mut stream, tcp_endpoint);

        let mut discovery_buffer = [0_u8; 512];
        let (discovery_len, discovery_client) = discovery_udp
            .recv_from(&mut discovery_buffer)
            .expect("WAN discovery request");
        let discovery_request = &discovery_buffer[..discovery_len];
        assert_eq!(&discovery_request[..2], &[0x00, 0x41]);
        let session_id = u32::from_be_bytes(discovery_request[2..6].try_into().unwrap());
        let xor_key = b'K';
        let payload = br#"{"is_oversea":false,"wan_addr":"198.51.100.20:41000"}"#;
        let mut discovery_response = discovery_request[..6].to_vec();
        discovery_response.extend(payload.iter().map(|byte| byte ^ xor_key));
        discovery_udp
            .send_to(&discovery_response, discovery_client)
            .expect("WAN discovery response");
        let discovered = decode_wan_discovery_response(&discovery_response, session_id, xor_key)
            .expect("fixture WAN response");

        let address_frame = read_frame(&mut stream);
        assert_eq!(address_frame[0], MessageType::Forward as u8);
        let decoded_frame: Vec<u8> = address_frame[3..].iter().map(|byte| byte ^ b'K').collect();
        let forwarded = decode_forward_payload(&decoded_frame).expect("client address forward");
        let client_info = decode_address_info_packet(forwarded.ip_packet()).expect("client info");
        assert_eq!(client_info.source(), local);
        assert_eq!(client_info.xor_key(), b'K');
        assert_ne!(client_info.instance_id(), 0);
        assert_eq!(client_info.endpoints().len(), 2);
        assert_eq!(client_info.endpoints()[0].address(), discovered.endpoint());
        assert_eq!(
            client_info.endpoints()[1].address().ip(),
            peer_endpoint.ip()
        );

        let peer_info = encode_address_info_packet(
            peer,
            0x4f,
            0x0102_0304,
            &[P2pEndpoint::new(peer_endpoint, EndpointGeo::China)],
        )
        .unwrap();
        let payload = encode_forward_v2(1, tcp_endpoint, &peer_info).unwrap();
        let frame = encode_post_auth_frame(MessageType::Forward, &payload, Some(b'K')).unwrap();
        stream.write_all(&frame).expect("peer address info");

        let mut buffer = [0_u8; 2048];
        let (length, client_endpoint) = peer_udp.recv_from(&mut buffer).expect("P2P echo");
        let echo = decode_echo(&buffer[..length]).expect("decode echo");
        assert!(!echo.is_echo_back());
        assert_eq!(echo.client_ip(), local);
        let echo_back = encode_echo_back(&buffer[..length], peer).unwrap();
        peer_udp
            .send_to(&echo_back, client_endpoint)
            .expect("send echo back");

        thread::sleep(Duration::from_millis(25));
        server_state.lock().unwrap().outbound.push_back(outbound);

        let (length, source) = peer_udp.recv_from(&mut buffer).expect("direct data");
        assert_eq!(source, client_endpoint);
        let direct = decode_data_datagram(&buffer[..length], 0x4f).expect("decode direct data");
        assert_eq!(direct.sender_xor_key(), b'K');
        assert_ne!(direct.sender_instance_id(), 0);
        let forwarded = decode_forward_payload(direct.forward_payload()).expect("legacy forward");
        assert_eq!(forwarded.version(), ForwardVersion::Legacy);
        assert_eq!(forwarded.ip_packet(), expected_outbound);
    });

    let request = AuthRequest::new("AB12345", "fixture", "router-linux", local.to_string());
    let session = TcpRoomSession::connect(
        tcp_endpoint,
        &request,
        SessionSettings::new(Duration::from_secs(1), Duration::from_millis(50)),
    )
    .expect("session");
    let tun = FakeTun {
        state: state.clone(),
    };
    let workers = BridgeWorkers::start(
        &tun,
        &session,
        local,
        "172.19.163.0/24",
        &members(),
        WorkerSettings::new(Duration::from_millis(1), Duration::from_secs(30)),
    )
    .expect("start bridge workers");

    server.join().expect("P2P fixture");
    workers.shutdown().expect("worker shutdown");
}

fn authenticate_fixture(stream: &mut std::net::TcpStream, endpoint: SocketAddr) {
    let request = read_frame(stream);
    let key = derive_proxy_key(&endpoint.to_string());
    let iv = &request[5..21];
    let ciphertext_end = request.len() - 16;
    let mut plaintext = request[21..ciphertext_end].to_vec();
    let tag = Tag::<U16>::from_slice(&request[ciphertext_end..]);
    Aes128Gcm16::new_from_slice(&key)
        .unwrap()
        .decrypt_in_place_detached(Nonce::<U16>::from_slice(iv), b"", &mut plaintext, tag)
        .expect("decrypt auth");

    let response = br#"{"result":0,"session_id":123456,"encrypt_method":"XOR","encrypt_key":"K"}"#;
    let mut frame = vec![MessageType::AuthResponse as u8];
    frame.extend_from_slice(&u16::try_from(response.len() + 1).unwrap().to_be_bytes());
    frame.push(0);
    frame.extend_from_slice(response);
    stream.write_all(&frame).expect("auth response");
}

fn read_frame(stream: &mut impl Read) -> Vec<u8> {
    let mut header = [0_u8; 3];
    stream.read_exact(&mut header).expect("frame header");
    let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).expect("frame body");
    let mut frame = header.to_vec();
    frame.extend(body);
    frame
}
