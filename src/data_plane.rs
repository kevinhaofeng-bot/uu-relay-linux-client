use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use thiserror::Error;

use crate::bootstrap::RoomMemberTable;
use crate::protocol::{ProtocolError, decode_forward_payload};

const IPV4_MINIMUM_HEADER_LEN: usize = 20;
const REPLAY_WINDOW_BITS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    Accepted,
    Duplicate,
}

#[derive(Debug)]
pub struct OutboundForward<'a> {
    packet_id: u32,
    transport_address: SocketAddr,
    ip_packet: &'a [u8],
}

impl OutboundForward<'_> {
    pub fn packet_id(&self) -> u32 {
        self.packet_id
    }

    pub fn transport_address(&self) -> SocketAddr {
        self.transport_address
    }

    pub fn ip_packet(&self) -> &[u8] {
        self.ip_packet
    }
}

#[derive(Debug)]
struct OutboundMember {
    transport_address: SocketAddr,
    packet_id: u32,
}

#[derive(Debug)]
pub struct OutboundRouter {
    local_address: Ipv4Addr,
    directed_broadcast: Ipv4Addr,
    broadcast_packet_id: u32,
    members: BTreeMap<Ipv4Addr, OutboundMember>,
}

impl OutboundRouter {
    pub fn new(
        local_address: Ipv4Addr,
        overlay_network: &str,
        members: &RoomMemberTable,
    ) -> Result<Self, DataPlaneError> {
        let network = Ipv4Network::parse(overlay_network)?;
        if !network.contains(local_address) {
            return Err(DataPlaneError::LocalAddressOutsideNetwork {
                address: local_address,
                network: overlay_network.to_owned(),
            });
        }
        let members = members
            .online()
            .iter()
            .map(|member| {
                (
                    member.client_lan_ip(),
                    OutboundMember {
                        transport_address: member.transport_address(),
                        packet_id: 0,
                    },
                )
            })
            .collect();
        Ok(Self {
            local_address,
            directed_broadcast: network.broadcast(),
            broadcast_packet_id: 0,
            members,
        })
    }

    pub fn route<'a>(
        &mut self,
        packet: &'a [u8],
    ) -> Result<Vec<OutboundForward<'a>>, DataPlaneError> {
        let header = Ipv4Header::parse(packet)?;
        if header.source != self.local_address {
            return Err(DataPlaneError::UnexpectedSource(header.source));
        }
        let packet = &packet[..header.total_len];
        if header.destination == Ipv4Addr::BROADCAST
            || header.destination == self.directed_broadcast
            || header.destination.is_multicast()
        {
            self.broadcast_packet_id = self.broadcast_packet_id.wrapping_add(1);
            let packet_id = self.broadcast_packet_id;
            return Ok(self
                .members
                .values()
                .map(|member| OutboundForward {
                    packet_id,
                    transport_address: member.transport_address,
                    ip_packet: packet,
                })
                .collect());
        }

        let member = self
            .members
            .get_mut(&header.destination)
            .ok_or(DataPlaneError::UnmappedDestination(header.destination))?;
        member.packet_id = member.packet_id.wrapping_add(1);
        Ok(vec![OutboundForward {
            packet_id: member.packet_id,
            transport_address: member.transport_address,
            ip_packet: packet,
        }])
    }

    pub fn update_members(&mut self, members: &RoomMemberTable) {
        let mut previous = std::mem::take(&mut self.members);
        self.members = members
            .online()
            .iter()
            .map(|member| {
                let mut state =
                    previous
                        .remove(&member.client_lan_ip())
                        .unwrap_or(OutboundMember {
                            transport_address: member.transport_address(),
                            packet_id: 0,
                        });
                state.transport_address = member.transport_address();
                (member.client_lan_ip(), state)
            })
            .collect();
    }
}

#[derive(Debug)]
pub struct InboundPacket<'a> {
    decision: ReplayDecision,
    ip_packet: &'a [u8],
}

impl InboundPacket<'_> {
    pub fn decision(&self) -> ReplayDecision {
        self.decision
    }

    pub fn ip_packet(&self) -> &[u8] {
        self.ip_packet
    }
}

#[derive(Debug, Default)]
struct InboundMember {
    unicast: ReplayWindow,
    broadcast: ReplayWindow,
}

#[derive(Debug)]
pub struct InboundFilter {
    local_address: Option<Ipv4Addr>,
    members: BTreeMap<Ipv4Addr, InboundMember>,
}

impl InboundFilter {
    pub fn new(members: &RoomMemberTable) -> Self {
        Self {
            local_address: None,
            members: members
                .online()
                .iter()
                .map(|member| (member.client_lan_ip(), InboundMember::default()))
                .collect(),
        }
    }

    pub fn with_local_address(local_address: Ipv4Addr, members: &RoomMemberTable) -> Self {
        let mut filter = Self::new(members);
        filter.local_address = Some(local_address);
        filter
    }

    pub fn inspect<'a>(&mut self, payload: &'a [u8]) -> Result<InboundPacket<'a>, DataPlaneError> {
        let forwarded = decode_forward_payload(payload)?;
        let header = Ipv4Header::parse(forwarded.ip_packet())?;
        if let Some(local_address) = self.local_address
            && header.destination != local_address
            && header.destination != Ipv4Addr::BROADCAST
            && !header.destination.is_multicast()
        {
            return Err(DataPlaneError::UnexpectedDestination(header.destination));
        }
        let member = self
            .members
            .get_mut(&header.source)
            .ok_or(DataPlaneError::UnknownMember(header.source))?;
        let replay =
            if header.destination == Ipv4Addr::BROADCAST || header.destination.is_multicast() {
                &mut member.broadcast
            } else {
                &mut member.unicast
            };
        Ok(InboundPacket {
            decision: replay.observe(forwarded.packet_id()),
            ip_packet: &forwarded.ip_packet()[..header.total_len],
        })
    }

    pub fn update_members(&mut self, members: &RoomMemberTable) {
        let mut previous = std::mem::take(&mut self.members);
        self.members = members
            .online()
            .iter()
            .map(|member| {
                (
                    member.client_lan_ip(),
                    previous.remove(&member.client_lan_ip()).unwrap_or_default(),
                )
            })
            .collect();
    }
}

#[derive(Debug, Default)]
struct ReplayWindow {
    base: Option<u32>,
    bitmap: u64,
}

impl ReplayWindow {
    fn observe(&mut self, packet_id: u32) -> ReplayDecision {
        let Some(base) = self.base else {
            self.reset(packet_id);
            return ReplayDecision::Accepted;
        };
        let distance = packet_id.wrapping_sub(base) as i32;
        if packet_id == 0 || distance < 0 {
            self.reset(packet_id);
            return ReplayDecision::Accepted;
        }
        let distance = distance as u32;
        if distance < REPLAY_WINDOW_BITS {
            let bit = 1_u64 << distance;
            if self.bitmap & bit != 0 {
                return ReplayDecision::Duplicate;
            }
            self.bitmap |= bit;
            return ReplayDecision::Accepted;
        }

        let slide = distance - (REPLAY_WINDOW_BITS - 1);
        self.bitmap = if slide >= REPLAY_WINDOW_BITS {
            0
        } else {
            self.bitmap >> slide
        };
        self.base = Some(base.wrapping_add(slide));
        self.bitmap |= 1_u64 << (REPLAY_WINDOW_BITS - 1);
        ReplayDecision::Accepted
    }

    fn reset(&mut self, packet_id: u32) {
        self.base = Some(packet_id);
        self.bitmap = 1;
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Header {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    total_len: usize,
}

impl Ipv4Header {
    fn parse(packet: &[u8]) -> Result<Self, DataPlaneError> {
        if packet.len() < IPV4_MINIMUM_HEADER_LEN {
            return Err(DataPlaneError::MalformedIpv4(
                "packet shorter than 20 bytes",
            ));
        }
        if packet[0] >> 4 != 4 {
            return Err(DataPlaneError::UnsupportedInnerIpVersion(packet[0] >> 4));
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < IPV4_MINIMUM_HEADER_LEN || header_len > packet.len() {
            return Err(DataPlaneError::MalformedIpv4("invalid header length"));
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < header_len || total_len > packet.len() {
            return Err(DataPlaneError::MalformedIpv4("invalid total length"));
        }
        Ok(Self {
            source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            total_len,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Network {
    network: u32,
    mask: u32,
}

impl Ipv4Network {
    fn parse(value: &str) -> Result<Self, DataPlaneError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| DataPlaneError::InvalidOverlayNetwork(value.to_owned()))?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| DataPlaneError::InvalidOverlayNetwork(value.to_owned()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| DataPlaneError::InvalidOverlayNetwork(value.to_owned()))?;
        if prefix > 32 {
            return Err(DataPlaneError::InvalidOverlayNetwork(value.to_owned()));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let address = u32::from(address);
        let network = address & mask;
        if address != network {
            return Err(DataPlaneError::InvalidOverlayNetwork(value.to_owned()));
        }
        Ok(Self { network, mask })
    }

    fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask == self.network
    }

    fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !self.mask)
    }
}

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("invalid overlay IPv4 network {0}")]
    InvalidOverlayNetwork(String),
    #[error("overlay address {address} is outside {network}")]
    LocalAddressOutsideNetwork { address: Ipv4Addr, network: String },
    #[error("malformed IPv4 packet: {0}")]
    MalformedIpv4(&'static str),
    #[error("unsupported inner IP version {0}")]
    UnsupportedInnerIpVersion(u8),
    #[error("outbound packet source {0} is not the assigned overlay address")]
    UnexpectedSource(Ipv4Addr),
    #[error("outbound packet destination {0} is not an online room member")]
    UnmappedDestination(Ipv4Addr),
    #[error("inbound packet source {0} is not an online room member")]
    UnknownMember(Ipv4Addr),
    #[error("inbound packet destination {0} is not this client or a broadcast address")]
    UnexpectedDestination(Ipv4Addr),
}
