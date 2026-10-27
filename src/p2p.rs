use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

use crate::bootstrap::RoomMemberTable;

const PPI_MAGIC: &[u8; 4] = b"PPI!";
const PPI_HEADER_LEN: usize = 5;
const ECHO_LEN: usize = 21;
const IPV4_HEADER_LEN: usize = 20;
const ADDRESS_FIXED_BODY_LEN: usize = 9;
const ENDPOINT_RECORD_LEN: usize = 19;
const ADDRESS_PROTOCOL: u8 = 253;
const ADDRESS_MESSAGE_TYPE: u8 = 0xa1;
const ADDRESS_TAIL: [u8; 2] = [0x67, 0x01];
const FORWARD_LEGACY_HEADER_LEN: usize = 5;
const DIRECT_ROUTE_TTL: Duration = Duration::from_secs(15);
const WAN_DISCOVERY_PROTOCOL: u8 = 0;
const WAN_DISCOVERY_MESSAGE: u8 = 0x41;
const WAN_DISCOVERY_HEADER_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointGeo {
    China,
    Other(u8),
}

impl EndpointGeo {
    fn wire_value(self) -> u8 {
        match self {
            Self::China => 1,
            Self::Other(value) => value,
        }
    }

    fn from_wire(value: u8) -> Self {
        if value == 1 {
            Self::China
        } else {
            Self::Other(value)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2pEndpoint {
    address: SocketAddr,
    geo: EndpointGeo,
}

impl P2pEndpoint {
    pub fn new(address: SocketAddr, geo: EndpointGeo) -> Self {
        Self { address, geo }
    }

    pub fn address(self) -> SocketAddr {
        self.address
    }

    pub fn geo(self) -> EndpointGeo {
        self.geo
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanDiscovery {
    endpoint: SocketAddr,
    geo: EndpointGeo,
}

impl WanDiscovery {
    pub fn endpoint(self) -> SocketAddr {
        self.endpoint
    }

    pub fn geo(self) -> EndpointGeo {
        self.geo
    }
}

#[derive(Deserialize)]
struct WanDiscoveryPayload {
    wan_addr: String,
    is_oversea: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo {
    source: Ipv4Addr,
    xor_key: u8,
    instance_id: u32,
    endpoints: Vec<P2pEndpoint>,
}

impl AddressInfo {
    pub fn source(&self) -> Ipv4Addr {
        self.source
    }

    pub fn xor_key(&self) -> u8 {
        self.xor_key
    }

    pub fn instance_id(&self) -> u32 {
        self.instance_id
    }

    pub fn endpoints(&self) -> &[P2pEndpoint] {
        &self.endpoints
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectData {
    sender_xor_key: u8,
    sender_instance_id: u32,
    forward_payload: Vec<u8>,
}

impl DirectData {
    pub fn sender_xor_key(&self) -> u8 {
        self.sender_xor_key
    }

    pub fn sender_instance_id(&self) -> u32 {
        self.sender_instance_id
    }

    pub fn forward_payload(&self) -> &[u8] {
        &self.forward_payload
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    echo_back: bool,
    timestamp_millis: u64,
    nonce: u32,
    client_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectTarget {
    overlay_ip: Ipv4Addr,
    endpoint: SocketAddr,
    xor_key: u8,
    instance_id: u32,
}

impl DirectTarget {
    pub fn overlay_ip(self) -> Ipv4Addr {
        self.overlay_ip
    }

    pub fn endpoint(self) -> SocketAddr {
        self.endpoint
    }

    pub fn xor_key(self) -> u8 {
        self.xor_key
    }

    pub fn instance_id(self) -> u32 {
        self.instance_id
    }
}

#[derive(Debug, Default)]
struct PeerState {
    relay_address: Option<SocketAddr>,
    xor_key: Option<u8>,
    instance_id: Option<u32>,
    candidates: BTreeSet<SocketAddr>,
    active_endpoint: Option<SocketAddr>,
    last_confirmed: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct PeerDirectory {
    peers: BTreeMap<Ipv4Addr, PeerState>,
}

impl PeerDirectory {
    pub fn new(members: &RoomMemberTable) -> Self {
        let mut directory = Self::default();
        directory.update_members(members);
        directory
    }

    pub fn update_members(&mut self, members: &RoomMemberTable) {
        let mut previous = std::mem::take(&mut self.peers);
        self.peers = members
            .online()
            .iter()
            .map(|member| {
                let overlay_ip = member.client_lan_ip();
                let mut peer = previous.remove(&overlay_ip).unwrap_or_default();
                peer.relay_address = Some(member.transport_address());
                (overlay_ip, peer)
            })
            .collect();
    }

    pub fn observe_address_info(&mut self, info: &AddressInfo) -> Result<(), P2pError> {
        let peer = self
            .peers
            .get_mut(&info.source)
            .ok_or(P2pError::UnknownPeer(info.source))?;
        let identity_changed =
            peer.xor_key != Some(info.xor_key) || peer.instance_id != Some(info.instance_id);
        peer.xor_key = Some(info.xor_key);
        peer.instance_id = Some(info.instance_id);
        peer.candidates = info
            .endpoints
            .iter()
            .map(|endpoint| endpoint.address())
            .collect();
        if identity_changed
            || peer
                .active_endpoint
                .is_some_and(|endpoint| !peer.candidates.contains(&endpoint))
        {
            peer.active_endpoint = None;
            peer.last_confirmed = None;
        }
        Ok(())
    }

    pub fn observe_echo(&mut self, overlay_ip: Ipv4Addr, source: SocketAddr) -> bool {
        let Some(peer) = self.peers.get_mut(&overlay_ip) else {
            return false;
        };
        if peer.xor_key.is_none()
            || peer.instance_id.is_none()
            || !peer.candidates.contains(&source)
        {
            return false;
        }
        peer.active_endpoint = Some(source);
        peer.last_confirmed = Some(Instant::now());
        true
    }

    pub fn observe_direct_data(
        &mut self,
        overlay_ip: Ipv4Addr,
        xor_key: u8,
        instance_id: u32,
        source: SocketAddr,
    ) -> Result<(), P2pError> {
        validate_identity(xor_key, instance_id)?;
        let peer = self
            .peers
            .get_mut(&overlay_ip)
            .ok_or(P2pError::UnknownPeer(overlay_ip))?;
        if let (Some(expected_key), Some(expected_instance)) = (peer.xor_key, peer.instance_id)
            && (expected_key != xor_key || expected_instance != instance_id)
        {
            return Err(P2pError::PeerIdentityMismatch(overlay_ip));
        }
        peer.xor_key = Some(xor_key);
        peer.instance_id = Some(instance_id);
        peer.candidates.insert(source);
        peer.active_endpoint = Some(source);
        peer.last_confirmed = Some(Instant::now());
        Ok(())
    }

    pub fn direct_target_for_relay(&self, relay_address: SocketAddr) -> Option<DirectTarget> {
        self.peers.iter().find_map(|(overlay_ip, peer)| {
            if peer.relay_address != Some(relay_address) {
                return None;
            }
            Some(DirectTarget {
                overlay_ip: *overlay_ip,
                endpoint: peer.active_endpoint?,
                xor_key: peer.xor_key?,
                instance_id: peer.instance_id?,
            })
            .filter(|_| {
                peer.last_confirmed
                    .is_some_and(|confirmed| confirmed.elapsed() <= DIRECT_ROUTE_TTL)
            })
        })
    }

    pub fn mark_direct_failed(&mut self, overlay_ip: Ipv4Addr, endpoint: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(&overlay_ip)
            && peer.active_endpoint == Some(endpoint)
        {
            peer.active_endpoint = None;
            peer.last_confirmed = None;
        }
    }

    pub fn is_known_peer(&self, overlay_ip: Ipv4Addr) -> bool {
        self.peers.contains_key(&overlay_ip)
    }

    pub fn probe_targets(&self) -> Vec<(Ipv4Addr, SocketAddr)> {
        self.peers
            .iter()
            .flat_map(|(overlay_ip, peer)| {
                peer.candidates
                    .iter()
                    .map(|endpoint| (*overlay_ip, *endpoint))
            })
            .collect()
    }

    pub fn candidates(&self, overlay_ip: Ipv4Addr) -> Option<Vec<SocketAddr>> {
        self.peers
            .get(&overlay_ip)
            .map(|peer| peer.candidates.iter().copied().collect())
    }
}

impl Echo {
    pub fn is_echo_back(self) -> bool {
        self.echo_back
    }

    pub fn timestamp_millis(self) -> u64 {
        self.timestamp_millis
    }

    pub fn nonce(self) -> u32 {
        self.nonce
    }

    pub fn client_ip(self) -> Ipv4Addr {
        self.client_ip
    }
}

pub fn encode_address_info_packet(
    source: Ipv4Addr,
    xor_key: u8,
    instance_id: u32,
    endpoints: &[P2pEndpoint],
) -> Result<Vec<u8>, P2pError> {
    validate_identity(xor_key, instance_id)?;
    if endpoints.is_empty() || endpoints.len() > u8::MAX as usize {
        return Err(P2pError::InvalidEndpointCount(endpoints.len()));
    }

    let packet_len = IPV4_HEADER_LEN
        .checked_add(ADDRESS_FIXED_BODY_LEN)
        .and_then(|length| length.checked_add(ENDPOINT_RECORD_LEN * endpoints.len()))
        .and_then(|length| length.checked_add(endpoints.len()))
        .ok_or(P2pError::PacketTooLarge)?;
    let total_len = u16::try_from(packet_len).map_err(|_| P2pError::PacketTooLarge)?;

    let mut packet = Vec::with_capacity(packet_len);
    packet.extend_from_slice(&[
        0x45,
        0,
        total_len.to_be_bytes()[0],
        total_len.to_be_bytes()[1],
        0,
        0,
        0,
        0,
        64,
        ADDRESS_PROTOCOL,
        0,
        0,
    ]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&Ipv4Addr::BROADCAST.octets());
    packet.push(ADDRESS_MESSAGE_TYPE);
    packet.push(xor_key);
    packet.push(endpoints.len() as u8);
    packet.extend_from_slice(&instance_id.to_be_bytes());

    for endpoint in endpoints {
        if endpoint.address.port() == 0 {
            return Err(P2pError::InvalidEndpoint(endpoint.address));
        }
        match endpoint.address.ip() {
            IpAddr::V4(address) => {
                packet.push(4);
                packet.extend_from_slice(&endpoint.address.port().to_be_bytes());
                packet.extend_from_slice(&address.octets());
                packet.extend_from_slice(&[0; 12]);
            }
            IpAddr::V6(address) => {
                packet.push(6);
                packet.extend_from_slice(&endpoint.address.port().to_be_bytes());
                packet.extend_from_slice(&address.octets());
            }
        }
    }
    packet.extend_from_slice(&ADDRESS_TAIL);
    packet.extend(endpoints.iter().map(|endpoint| endpoint.geo.wire_value()));
    Ok(packet)
}

pub fn encode_wan_discovery_request(session_id: u32, xor_key: u8) -> Result<Vec<u8>, P2pError> {
    if session_id == 0 {
        return Err(P2pError::InvalidSessionId);
    }
    if xor_key == 0 {
        return Err(P2pError::InvalidXorKey);
    }
    let mut request = Vec::with_capacity(WAN_DISCOVERY_HEADER_LEN + 2);
    request.push(WAN_DISCOVERY_PROTOCOL);
    request.push(WAN_DISCOVERY_MESSAGE);
    request.extend_from_slice(&session_id.to_be_bytes());
    request.extend(b"{}".iter().map(|byte| byte ^ xor_key));
    Ok(request)
}

pub fn decode_wan_discovery_response(
    datagram: &[u8],
    session_id: u32,
    xor_key: u8,
) -> Result<WanDiscovery, P2pError> {
    if session_id == 0 {
        return Err(P2pError::InvalidSessionId);
    }
    if xor_key == 0 {
        return Err(P2pError::InvalidXorKey);
    }
    if datagram.len() <= WAN_DISCOVERY_HEADER_LEN
        || datagram[0] != WAN_DISCOVERY_PROTOCOL
        || datagram[1] != WAN_DISCOVERY_MESSAGE
        || datagram[2..WAN_DISCOVERY_HEADER_LEN] != session_id.to_be_bytes()
    {
        return Err(P2pError::InvalidWanDiscoveryHeader);
    }
    let clear = datagram[WAN_DISCOVERY_HEADER_LEN..]
        .iter()
        .map(|byte| byte ^ xor_key)
        .collect::<Vec<_>>();
    let payload: WanDiscoveryPayload =
        serde_json::from_slice(&clear).map_err(|_| P2pError::InvalidWanDiscoveryJson)?;
    let endpoint = payload
        .wan_addr
        .parse::<SocketAddr>()
        .map_err(|_| P2pError::InvalidWanAddress)?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
        return Err(P2pError::InvalidWanAddress);
    }
    Ok(WanDiscovery {
        endpoint,
        geo: if payload.is_oversea {
            EndpointGeo::Other(2)
        } else {
            EndpointGeo::China
        },
    })
}

pub fn decode_address_info_packet(packet: &[u8]) -> Result<AddressInfo, P2pError> {
    if packet.len() < IPV4_HEADER_LEN + ADDRESS_FIXED_BODY_LEN + ENDPOINT_RECORD_LEN + 1 {
        return Err(P2pError::Truncated("address info"));
    }
    if packet[0] != 0x45 || packet[9] != ADDRESS_PROTOCOL {
        return Err(P2pError::InvalidAddressEnvelope);
    }
    let declared_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if declared_len != packet.len() {
        return Err(P2pError::LengthMismatch {
            declared: declared_len,
            actual: packet.len(),
        });
    }
    if packet[16..20] != Ipv4Addr::BROADCAST.octets()
        || packet[IPV4_HEADER_LEN] != ADDRESS_MESSAGE_TYPE
    {
        return Err(P2pError::InvalidAddressEnvelope);
    }

    let xor_key = packet[21];
    let endpoint_count = packet[22] as usize;
    let instance_id = u32::from_be_bytes(packet[23..27].try_into().expect("fixed slice"));
    validate_identity(xor_key, instance_id)?;
    if endpoint_count == 0 {
        return Err(P2pError::InvalidEndpointCount(0));
    }
    let expected_len = IPV4_HEADER_LEN
        + ADDRESS_FIXED_BODY_LEN
        + ENDPOINT_RECORD_LEN * endpoint_count
        + endpoint_count;
    if packet.len() != expected_len {
        return Err(P2pError::LengthMismatch {
            declared: expected_len,
            actual: packet.len(),
        });
    }

    let records_start = 27;
    let tail_start = records_start + ENDPOINT_RECORD_LEN * endpoint_count;
    if packet[tail_start..tail_start + 2] != ADDRESS_TAIL {
        return Err(P2pError::InvalidAddressTail);
    }
    let geos = &packet[tail_start + 2..];
    let mut endpoints = Vec::with_capacity(endpoint_count);
    for (index, geo) in geos.iter().copied().enumerate() {
        let offset = records_start + index * ENDPOINT_RECORD_LEN;
        let family = packet[offset];
        let port = u16::from_be_bytes([packet[offset + 1], packet[offset + 2]]);
        if port == 0 {
            return Err(P2pError::InvalidEndpointPort);
        }
        let address = match family {
            4 => {
                if packet[offset + 7..offset + ENDPOINT_RECORD_LEN]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(P2pError::InvalidIpv4Padding);
                }
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset + 3],
                    packet[offset + 4],
                    packet[offset + 5],
                    packet[offset + 6],
                ))
            }
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[offset + 3..offset + ENDPOINT_RECORD_LEN])
                    .expect("fixed slice"),
            )),
            other => return Err(P2pError::UnsupportedAddressFamily(other)),
        };
        endpoints.push(P2pEndpoint::new(
            SocketAddr::new(address, port),
            EndpointGeo::from_wire(geo),
        ));
    }

    Ok(AddressInfo {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        xor_key,
        instance_id,
        endpoints,
    })
}

pub fn encode_data_datagram(
    sender_xor_key: u8,
    sender_instance_id: u32,
    receiver_xor_key: u8,
    forward_payload: &[u8],
) -> Result<Vec<u8>, P2pError> {
    validate_identity(sender_xor_key, sender_instance_id)?;
    if receiver_xor_key == 0 {
        return Err(P2pError::InvalidXorKey);
    }
    validate_forward_payload(forward_payload)?;

    let mut datagram = Vec::with_capacity(PPI_HEADER_LEN + 5 + forward_payload.len());
    datagram.extend_from_slice(PPI_MAGIC);
    datagram.push(2);
    datagram.push(sender_xor_key);
    datagram.extend_from_slice(&sender_instance_id.to_be_bytes());
    datagram.extend_from_slice(forward_payload);
    for byte in &mut datagram[PPI_HEADER_LEN..] {
        *byte ^= receiver_xor_key;
    }
    Ok(datagram)
}

pub fn decode_data_datagram(datagram: &[u8], local_xor_key: u8) -> Result<DirectData, P2pError> {
    if local_xor_key == 0 {
        return Err(P2pError::InvalidXorKey);
    }
    validate_ppi_header(datagram, 2)?;
    if datagram.len() < PPI_HEADER_LEN + 5 + FORWARD_LEGACY_HEADER_LEN {
        return Err(P2pError::Truncated("direct data"));
    }
    let mut decoded = datagram[PPI_HEADER_LEN..].to_vec();
    for byte in &mut decoded {
        *byte ^= local_xor_key;
    }
    let sender_xor_key = decoded[0];
    let sender_instance_id = u32::from_be_bytes(decoded[1..5].try_into().expect("fixed slice"));
    validate_identity(sender_xor_key, sender_instance_id)?;
    validate_forward_payload(&decoded[5..])?;
    Ok(DirectData {
        sender_xor_key,
        sender_instance_id,
        forward_payload: decoded.split_off(5),
    })
}

pub fn encode_echo(timestamp_millis: u64, nonce: u32, client_ip: Ipv4Addr) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(ECHO_LEN);
    datagram.extend_from_slice(PPI_MAGIC);
    datagram.push(0);
    datagram.extend_from_slice(&timestamp_millis.to_le_bytes());
    datagram.extend_from_slice(&nonce.to_le_bytes());
    datagram.extend_from_slice(&client_ip.octets());
    datagram
}

pub fn encode_echo_back(echo: &[u8], local_ip: Ipv4Addr) -> Result<Vec<u8>, P2pError> {
    let decoded = decode_echo(echo)?;
    if decoded.is_echo_back() {
        return Err(P2pError::UnexpectedEchoBack);
    }
    let mut response = echo.to_vec();
    response[4] = 1;
    response[17..21].copy_from_slice(&local_ip.octets());
    Ok(response)
}

pub fn decode_echo(datagram: &[u8]) -> Result<Echo, P2pError> {
    if datagram.len() != ECHO_LEN {
        return Err(P2pError::LengthMismatch {
            declared: ECHO_LEN,
            actual: datagram.len(),
        });
    }
    if &datagram[..4] != PPI_MAGIC || !matches!(datagram[4], 0 | 1) {
        return Err(P2pError::InvalidPpiHeader);
    }
    Ok(Echo {
        echo_back: datagram[4] == 1,
        timestamp_millis: u64::from_le_bytes(datagram[5..13].try_into().expect("fixed slice")),
        nonce: u32::from_le_bytes(datagram[13..17].try_into().expect("fixed slice")),
        client_ip: Ipv4Addr::new(datagram[17], datagram[18], datagram[19], datagram[20]),
    })
}

fn validate_ppi_header(datagram: &[u8], message_type: u8) -> Result<(), P2pError> {
    if datagram.len() < PPI_HEADER_LEN || &datagram[..4] != PPI_MAGIC || datagram[4] != message_type
    {
        return Err(P2pError::InvalidPpiHeader);
    }
    Ok(())
}

fn validate_identity(xor_key: u8, instance_id: u32) -> Result<(), P2pError> {
    if xor_key == 0 {
        return Err(P2pError::InvalidXorKey);
    }
    if instance_id == 0 {
        return Err(P2pError::InvalidInstanceId);
    }
    Ok(())
}

fn validate_forward_payload(payload: &[u8]) -> Result<(), P2pError> {
    if payload.len() < FORWARD_LEGACY_HEADER_LEN {
        return Err(P2pError::Truncated("forward payload"));
    }
    if payload[0] != 1 {
        return Err(P2pError::UnsupportedForwardVersion(payload[0]));
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum P2pError {
    #[error("invalid PPI datagram header")]
    InvalidPpiHeader,
    #[error("invalid address-info IPv4 envelope")]
    InvalidAddressEnvelope,
    #[error("invalid address-info trailer")]
    InvalidAddressTail,
    #[error("invalid IPv4 endpoint padding")]
    InvalidIpv4Padding,
    #[error("invalid XOR key")]
    InvalidXorKey,
    #[error("invalid instance id")]
    InvalidInstanceId,
    #[error("invalid session id")]
    InvalidSessionId,
    #[error("invalid endpoint count: {0}")]
    InvalidEndpointCount(usize),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(SocketAddr),
    #[error("invalid endpoint port")]
    InvalidEndpointPort,
    #[error("invalid WAN discovery header")]
    InvalidWanDiscoveryHeader,
    #[error("invalid WAN discovery JSON")]
    InvalidWanDiscoveryJson,
    #[error("invalid WAN discovery address")]
    InvalidWanAddress,
    #[error("unsupported endpoint address family: {0}")]
    UnsupportedAddressFamily(u8),
    #[error("unsupported direct forward version: {0}")]
    UnsupportedForwardVersion(u8),
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("length mismatch: expected {declared}, got {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("packet too large")]
    PacketTooLarge,
    #[error("received echo_back where echo was required")]
    UnexpectedEchoBack,
    #[error("P2P message came from unknown overlay peer {0}")]
    UnknownPeer(Ipv4Addr),
    #[error("P2P identity changed unexpectedly for peer {0}")]
    PeerIdentityMismatch(Ipv4Addr),
}
