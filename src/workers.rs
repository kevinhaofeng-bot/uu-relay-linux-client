use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::bootstrap::RoomMemberTable;
use crate::p2p::{
    EndpointGeo, P2pEndpoint, P2pError, PeerDirectory, decode_address_info_packet,
    decode_data_datagram, decode_echo, decode_wan_discovery_response, encode_address_info_packet,
    encode_data_datagram, encode_echo, encode_echo_back, encode_wan_discovery_request,
};
use crate::protocol::{
    ForwardVersion, MessageType, ProtocolError, decode_forward_payload, encode_forward_legacy,
};
use crate::pump::{ForwardSink, InboundPump, OutboundPump, PumpError};
use crate::session::{SessionError, TcpRoomReceiver, TcpRoomSender, TcpRoomSession};
use crate::tun::{TunDevice, TunError};

const MAX_IP_PACKET: usize = u16::MAX as usize;
const P2P_CONTROL_PROTOCOL: u8 = 253;
const P2P_ADDRESS_MESSAGE: u8 = 0xa1;
const P2P_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
const P2P_PROBE_INTERVAL: Duration = Duration::from_secs(5);
const WAN_DISCOVERY_ATTEMPTS: usize = 3;
const WAN_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(300);

#[derive(Debug, Clone)]
struct LocalP2pAnnounce {
    overlay_address: Ipv4Addr,
    endpoints: Vec<P2pEndpoint>,
}

#[derive(Debug, Clone, Copy)]
pub struct WorkerSettings {
    idle_sleep: Duration,
    keepalive_interval: Duration,
}

impl WorkerSettings {
    pub fn new(idle_sleep: Duration, keepalive_interval: Duration) -> Self {
        Self {
            idle_sleep,
            keepalive_interval,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerDirection {
    Outbound,
    Inbound,
    P2p,
}

#[derive(Debug)]
pub struct WorkerFailure {
    direction: WorkerDirection,
    error: WorkerLoopError,
}

impl WorkerFailure {
    pub fn direction(&self) -> WorkerDirection {
        self.direction
    }

    pub fn error(&self) -> &WorkerLoopError {
        &self.error
    }
}

pub struct BridgeWorkers {
    stop: Arc<AtomicBool>,
    outbound_updates: Sender<RoomMemberTable>,
    directory: Arc<Mutex<PeerDirectory>>,
    inbound: Arc<Mutex<InboundPump>>,
    failures: Receiver<WorkerFailure>,
    handles: Vec<JoinHandle<()>>,
}

impl BridgeWorkers {
    pub fn start(
        tun: &dyn TunDevice,
        session: &TcpRoomSession,
        local_address: Ipv4Addr,
        overlay_network: &str,
        members: &RoomMemberTable,
        settings: WorkerSettings,
    ) -> Result<Self, WorkerStartError> {
        let tun_reader = tun.try_clone_device()?;
        let tcp_tun_writer = tun.try_clone_device()?;
        let udp_tun_writer = tun.try_clone_device()?;
        let (sender, receiver) = session.try_split()?;
        let local_xor_key = session
            .p2p_xor_key()
            .ok_or(WorkerStartError::MissingP2pXorKey)?;
        let local_instance_id = random_nonzero_u32()?;
        let transport_ip = session.local_transport_address()?.ip();
        let udp = UdpSocket::bind(SocketAddr::new(transport_ip, 0))?;
        let local_endpoint = udp.local_addr()?;
        udp.set_read_timeout(Some(WAN_DISCOVERY_TIMEOUT))?;
        let discovered = discover_wan_endpoint(
            &udp,
            session.remote_transport_address()?,
            session
                .p2p_session_id()
                .ok_or(WorkerStartError::MissingP2pSessionId)?,
            local_xor_key,
        );
        udp.set_read_timeout(Some(settings.idle_sleep.max(Duration::from_millis(10))))?;
        let local_geo = discovered
            .as_ref()
            .map(|endpoint| endpoint.geo())
            .unwrap_or(EndpointGeo::China);
        let mut local_endpoints = discovered
            .into_iter()
            .map(|endpoint| P2pEndpoint::new(endpoint.endpoint(), endpoint.geo()))
            .collect::<Vec<_>>();
        if !local_endpoints
            .iter()
            .any(|endpoint| endpoint.address() == local_endpoint)
        {
            local_endpoints.push(P2pEndpoint::new(local_endpoint, local_geo));
        }
        let outbound_udp = udp.try_clone()?;
        let tcp_udp = udp.try_clone()?;

        let outbound = OutboundPump::new(local_address, overlay_network, members)?;
        let inbound = Arc::new(Mutex::new(InboundPump::new(local_address, members)));
        let directory = Arc::new(Mutex::new(PeerDirectory::new(members)));
        let stop = Arc::new(AtomicBool::new(false));
        let (outbound_updates, outbound_rx) = mpsc::channel();
        let (failure_tx, failures) = mpsc::channel();

        let outbound_stop = stop.clone();
        let outbound_failure_tx = failure_tx.clone();
        let outbound_directory = directory.clone();
        let outbound_handle = thread::spawn(move || {
            let sink = P2pForwardSink::new(
                sender,
                outbound_udp,
                outbound_directory,
                local_xor_key,
                local_instance_id,
            );
            if let Err(error) = run_outbound(
                tun_reader,
                sink,
                outbound,
                outbound_rx,
                LocalP2pAnnounce {
                    overlay_address: local_address,
                    endpoints: local_endpoints,
                },
                &outbound_stop,
                settings,
            ) {
                outbound_stop.store(true, Ordering::Release);
                let _ = outbound_failure_tx.send(WorkerFailure {
                    direction: WorkerDirection::Outbound,
                    error,
                });
            }
        });

        let inbound_stop = stop.clone();
        let inbound_failure_tx = failure_tx.clone();
        let inbound_directory = directory.clone();
        let tcp_inbound = inbound.clone();
        let inbound_handle = thread::spawn(move || {
            if let Err(error) = run_inbound_tcp(
                tcp_tun_writer,
                receiver,
                tcp_udp,
                tcp_inbound,
                inbound_directory,
                local_address,
                &inbound_stop,
            ) {
                inbound_stop.store(true, Ordering::Release);
                let _ = inbound_failure_tx.send(WorkerFailure {
                    direction: WorkerDirection::Inbound,
                    error,
                });
            }
        });

        let p2p_stop = stop.clone();
        let p2p_directory = directory.clone();
        let udp_inbound = inbound.clone();
        let p2p_handle = thread::spawn(move || {
            if let Err(error) = run_inbound_udp(
                udp_tun_writer,
                udp,
                udp_inbound,
                p2p_directory,
                local_xor_key,
                local_address,
                &p2p_stop,
            ) {
                p2p_stop.store(true, Ordering::Release);
                let _ = failure_tx.send(WorkerFailure {
                    direction: WorkerDirection::P2p,
                    error,
                });
            }
        });

        Ok(Self {
            stop,
            outbound_updates,
            directory,
            inbound,
            failures,
            handles: vec![outbound_handle, inbound_handle, p2p_handle],
        })
    }

    pub fn update_members(&self, members: &RoomMemberTable) -> Result<(), WorkerStartError> {
        self.outbound_updates
            .send(members.clone())
            .map_err(|_| WorkerStartError::WorkerStopped)?;
        self.directory
            .lock()
            .map_err(|_| WorkerStartError::StatePoisoned)?
            .update_members(members);
        self.inbound
            .lock()
            .map_err(|_| WorkerStartError::StatePoisoned)?
            .update_members(members);
        Ok(())
    }

    pub fn wait_for_failure(&self, timeout: Duration) -> Option<WorkerFailure> {
        self.failures.recv_timeout(timeout).ok()
    }

    pub fn shutdown(mut self) -> Result<(), WorkerStartError> {
        self.stop.store(true, Ordering::Release);
        for handle in self.handles.drain(..) {
            handle
                .join()
                .map_err(|_| WorkerStartError::WorkerPanicked)?;
        }
        Ok(())
    }
}

struct P2pForwardSink {
    tcp: TcpRoomSender,
    udp: UdpSocket,
    directory: Arc<Mutex<PeerDirectory>>,
    local_xor_key: u8,
    local_instance_id: u32,
}

impl P2pForwardSink {
    fn new(
        tcp: TcpRoomSender,
        udp: UdpSocket,
        directory: Arc<Mutex<PeerDirectory>>,
        local_xor_key: u8,
        local_instance_id: u32,
    ) -> Self {
        Self {
            tcp,
            udp,
            directory,
            local_xor_key,
            local_instance_id,
        }
    }

    fn send_keepalive(&mut self) -> Result<(), SessionError> {
        self.tcp.send_keepalive()
    }

    fn send_probe(&self, local_overlay_ip: Ipv4Addr, endpoint: SocketAddr, nonce: u32) {
        let echo = encode_echo(unix_millis(), nonce, local_overlay_ip);
        let _ = self.udp.send_to(&echo, endpoint);
    }
}

impl ForwardSink for P2pForwardSink {
    type Error = HybridSinkError;

    fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        let forwarded = decode_forward_payload(payload)?;
        if is_p2p_control_packet(forwarded.ip_packet()) {
            return self
                .tcp
                .send_forward_payload(payload)
                .map_err(HybridSinkError::Session);
        }
        let Some(relay_address) = forwarded.transport_address() else {
            return self
                .tcp
                .send_forward_payload(payload)
                .map_err(HybridSinkError::Session);
        };
        let target = self
            .directory
            .lock()
            .map_err(|_| HybridSinkError::StatePoisoned)?
            .direct_target_for_relay(relay_address);
        let Some(target) = target else {
            return self
                .tcp
                .send_forward_payload(payload)
                .map_err(HybridSinkError::Session);
        };

        let legacy = encode_forward_legacy(forwarded.packet_id(), forwarded.ip_packet())?;
        let datagram = encode_data_datagram(
            self.local_xor_key,
            self.local_instance_id,
            target.xor_key(),
            &legacy,
        )?;
        match self.udp.send_to(&datagram, target.endpoint()) {
            Ok(length) if length == datagram.len() => Ok(()),
            _ => {
                self.directory
                    .lock()
                    .map_err(|_| HybridSinkError::StatePoisoned)?
                    .mark_direct_failed(target.overlay_ip(), target.endpoint());
                self.tcp
                    .send_forward_payload(payload)
                    .map_err(HybridSinkError::Session)
            }
        }
    }
}

fn run_outbound(
    mut tun: Box<dyn TunDevice>,
    mut sink: P2pForwardSink,
    mut pump: OutboundPump,
    updates: Receiver<RoomMemberTable>,
    announce: LocalP2pAnnounce,
    stop: &AtomicBool,
    settings: WorkerSettings,
) -> Result<(), WorkerLoopError> {
    let address_info = encode_address_info_packet(
        announce.overlay_address,
        sink.local_xor_key,
        sink.local_instance_id,
        &announce.endpoints,
    )?;
    pump.forward(&address_info, &mut sink)?;
    let mut buffer = vec![0_u8; MAX_IP_PACKET];
    let mut last_keepalive = Instant::now();
    let mut last_announce = Instant::now();
    let mut last_probe = Instant::now();
    let mut probe_nonce = sink.local_instance_id;
    while !stop.load(Ordering::Acquire) {
        receive_updates(&updates, |members| pump.update_members(&members));
        if last_keepalive.elapsed() >= settings.keepalive_interval {
            sink.send_keepalive()?;
            last_keepalive = Instant::now();
        }
        if last_announce.elapsed() >= P2P_ANNOUNCE_INTERVAL {
            pump.forward(&address_info, &mut sink)?;
            last_announce = Instant::now();
        }
        if last_probe.elapsed() >= P2P_PROBE_INTERVAL {
            let targets = sink
                .directory
                .lock()
                .map_err(|_| WorkerLoopError::StatePoisoned)?
                .probe_targets();
            for (_, endpoint) in targets {
                probe_nonce = probe_nonce.wrapping_add(1);
                sink.send_probe(announce.overlay_address, endpoint, probe_nonce);
            }
            last_probe = Instant::now();
        }
        if let Some(length) = tun.read_packet(&mut buffer)? {
            match pump.forward(&buffer[..length], &mut sink) {
                Ok(_) => {}
                Err(PumpError::DataPlane(_)) => {}
                Err(error) => return Err(WorkerLoopError::Pump(error)),
            }
        } else {
            thread::sleep(settings.idle_sleep);
        }
    }
    tun.close()?;
    Ok(())
}

fn discover_wan_endpoint(
    udp: &UdpSocket,
    server: SocketAddr,
    session_id: u32,
    xor_key: u8,
) -> Option<crate::p2p::WanDiscovery> {
    let request = encode_wan_discovery_request(session_id, xor_key).ok()?;
    let mut response = [0_u8; 2048];
    for _ in 0..WAN_DISCOVERY_ATTEMPTS {
        if udp.send_to(&request, server).ok()? != request.len() {
            return None;
        }
        match udp.recv_from(&mut response) {
            Ok((length, source)) if source == server => {
                if let Ok(discovered) =
                    decode_wan_discovery_response(&response[..length], session_id, xor_key)
                {
                    return Some(discovered);
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return None,
        }
    }
    None
}

fn run_inbound_tcp(
    mut tun: Box<dyn TunDevice>,
    mut receiver: TcpRoomReceiver,
    udp: UdpSocket,
    inbound: Arc<Mutex<InboundPump>>,
    directory: Arc<Mutex<PeerDirectory>>,
    local_address: Ipv4Addr,
    stop: &AtomicBool,
) -> Result<(), WorkerLoopError> {
    let mut nonce = 0_u32;
    while !stop.load(Ordering::Acquire) {
        let frame = match receiver.receive() {
            Ok(frame) => frame,
            Err(error) if error.is_timeout() => continue,
            Err(error) => return Err(WorkerLoopError::Session(error)),
        };
        match frame.message_type() {
            MessageType::Forward => {
                let forwarded = decode_forward_payload(frame.payload())?;
                if is_address_info_packet(forwarded.ip_packet()) {
                    let info = match decode_address_info_packet(forwarded.ip_packet()) {
                        Ok(info) => info,
                        Err(_) => continue,
                    };
                    let candidates = {
                        let mut peers = directory
                            .lock()
                            .map_err(|_| WorkerLoopError::StatePoisoned)?;
                        if peers.observe_address_info(&info).is_err() {
                            continue;
                        }
                        peers.candidates(info.source()).unwrap_or_default()
                    };
                    for endpoint in candidates {
                        nonce = nonce.wrapping_add(1);
                        let echo = encode_echo(unix_millis(), nonce, local_address);
                        let _ = udp.send_to(&echo, endpoint);
                    }
                    continue;
                }
                let result = inbound
                    .lock()
                    .map_err(|_| WorkerLoopError::StatePoisoned)?
                    .inject(frame.payload(), tun.as_mut());
                match result {
                    Ok(_) | Err(PumpError::DataPlane(_)) => {}
                    Err(error) => return Err(WorkerLoopError::Pump(error)),
                }
            }
            MessageType::Keepalive => {}
            other => return Err(WorkerLoopError::UnexpectedMessage(other)),
        }
    }
    tun.close()?;
    Ok(())
}

fn run_inbound_udp(
    mut tun: Box<dyn TunDevice>,
    udp: UdpSocket,
    inbound: Arc<Mutex<InboundPump>>,
    directory: Arc<Mutex<PeerDirectory>>,
    local_xor_key: u8,
    local_address: Ipv4Addr,
    stop: &AtomicBool,
) -> Result<(), WorkerLoopError> {
    let mut buffer = vec![0_u8; MAX_IP_PACKET];
    while !stop.load(Ordering::Acquire) {
        let (length, source) = match udp.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(WorkerLoopError::Io(error)),
        };
        let datagram = &buffer[..length];
        let Some(message_type) = datagram.get(4).copied() else {
            continue;
        };
        match message_type {
            0 | 1 => {
                let echo = match decode_echo(datagram) {
                    Ok(echo) => echo,
                    Err(_) => continue,
                };
                let known = directory
                    .lock()
                    .map_err(|_| WorkerLoopError::StatePoisoned)?
                    .is_known_peer(echo.client_ip());
                if !known {
                    continue;
                }
                if !echo.is_echo_back()
                    && let Ok(response) = encode_echo_back(datagram, local_address)
                {
                    let _ = udp.send_to(&response, source);
                }
                let _ = directory
                    .lock()
                    .map_err(|_| WorkerLoopError::StatePoisoned)?
                    .observe_echo(echo.client_ip(), source);
            }
            2 => {
                let direct = match decode_data_datagram(datagram, local_xor_key) {
                    Ok(direct) => direct,
                    Err(_) => continue,
                };
                let forwarded = match decode_forward_payload(direct.forward_payload()) {
                    Ok(forwarded) if forwarded.version() == ForwardVersion::Legacy => forwarded,
                    _ => continue,
                };
                let Some(peer_ip) = ipv4_source(forwarded.ip_packet()) else {
                    continue;
                };
                if directory
                    .lock()
                    .map_err(|_| WorkerLoopError::StatePoisoned)?
                    .observe_direct_data(
                        peer_ip,
                        direct.sender_xor_key(),
                        direct.sender_instance_id(),
                        source,
                    )
                    .is_err()
                {
                    continue;
                }
                let result = inbound
                    .lock()
                    .map_err(|_| WorkerLoopError::StatePoisoned)?
                    .inject(direct.forward_payload(), tun.as_mut());
                match result {
                    Ok(_) | Err(PumpError::DataPlane(_)) => {}
                    Err(error) => return Err(WorkerLoopError::Pump(error)),
                }
            }
            _ => {}
        }
    }
    tun.close()?;
    Ok(())
}

fn is_p2p_control_packet(packet: &[u8]) -> bool {
    packet.len() >= 21 && packet[0] >> 4 == 4 && packet[9] == P2P_CONTROL_PROTOCOL
}

fn is_address_info_packet(packet: &[u8]) -> bool {
    is_p2p_control_packet(packet) && packet[20] == P2P_ADDRESS_MESSAGE
}

fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    (packet.len() >= 20 && packet[0] >> 4 == 4)
        .then(|| Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn random_nonzero_u32() -> Result<u32, WorkerStartError> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(|_| WorkerStartError::EntropyUnavailable)?;
    let value = u32::from_ne_bytes(bytes);
    Ok(if value == 0 { 1 } else { value })
}

fn receive_updates(updates: &Receiver<RoomMemberTable>, mut apply: impl FnMut(RoomMemberTable)) {
    loop {
        match updates.try_recv() {
            Ok(members) => apply(members),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

#[derive(Debug, Error)]
enum HybridSinkError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    P2p(#[from] P2pError),
    #[error("P2P peer state lock was poisoned")]
    StatePoisoned,
}

#[derive(Debug, Error)]
pub enum WorkerStartError {
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Pump(#[from] PumpError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    P2p(#[from] P2pError),
    #[error("authenticated room did not negotiate a P2P XOR key")]
    MissingP2pXorKey,
    #[error("authenticated room did not negotiate a P2P session id")]
    MissingP2pSessionId,
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
    #[error("packet worker has stopped")]
    WorkerStopped,
    #[error("packet worker state lock was poisoned")]
    StatePoisoned,
    #[error("packet worker panicked")]
    WorkerPanicked,
}

#[derive(Debug, Error)]
pub enum WorkerLoopError {
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Pump(#[from] PumpError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    P2p(#[from] P2pError),
    #[error("P2P UDP I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("packet worker state lock was poisoned")]
    StatePoisoned,
    #[error("unexpected post-authentication message {0:?}")]
    UnexpectedMessage(MessageType),
}
