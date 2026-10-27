use std::fmt::Display;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::bootstrap::RoomMemberTable;
use crate::data_plane::{DataPlaneError, InboundFilter, OutboundRouter, ReplayDecision};
use crate::protocol::{ProtocolError, encode_forward_v2};
use crate::session::{SessionError, TcpRoomSender};
use crate::tun::{TunDevice, TunError};

pub trait ForwardSink {
    type Error: Display;

    fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error>;
}

pub trait PacketSink {
    type Error: Display;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}

impl ForwardSink for TcpRoomSender {
    type Error = SessionError;

    fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        TcpRoomSender::send_forward_payload(self, payload)
    }
}

impl<T> PacketSink for T
where
    T: TunDevice + ?Sized,
{
    type Error = TunError;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        TunDevice::write_packet(self, packet)
    }
}

#[derive(Debug)]
pub struct OutboundPump {
    router: OutboundRouter,
}

impl OutboundPump {
    pub fn new(
        local_address: Ipv4Addr,
        overlay_network: &str,
        members: &RoomMemberTable,
    ) -> Result<Self, PumpError> {
        Ok(Self {
            router: OutboundRouter::new(local_address, overlay_network, members)?,
        })
    }

    pub fn forward<S>(&mut self, packet: &[u8], sink: &mut S) -> Result<usize, PumpError>
    where
        S: ForwardSink,
    {
        let routes = self.router.route(packet)?;
        let count = routes.len();
        for route in routes {
            let payload = encode_forward_v2(
                route.packet_id(),
                route.transport_address(),
                route.ip_packet(),
            )?;
            sink.send_forward_payload(&payload)
                .map_err(|error| PumpError::Sink(error.to_string()))?;
        }
        Ok(count)
    }

    pub fn update_members(&mut self, members: &RoomMemberTable) {
        self.router.update_members(members);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Injected,
    Duplicate,
}

#[derive(Debug)]
pub struct InboundPump {
    filter: InboundFilter,
}

impl InboundPump {
    pub fn new(local_address: Ipv4Addr, members: &RoomMemberTable) -> Self {
        Self {
            filter: InboundFilter::with_local_address(local_address, members),
        }
    }

    pub fn inject<S>(&mut self, payload: &[u8], sink: &mut S) -> Result<ReceiveOutcome, PumpError>
    where
        S: PacketSink + ?Sized,
    {
        let packet = self.filter.inspect(payload)?;
        if packet.decision() == ReplayDecision::Duplicate {
            return Ok(ReceiveOutcome::Duplicate);
        }
        sink.write_packet(packet.ip_packet())
            .map_err(|error| PumpError::Sink(error.to_string()))?;
        Ok(ReceiveOutcome::Injected)
    }

    pub fn update_members(&mut self, members: &RoomMemberTable) {
        self.filter.update_members(members);
    }
}

#[derive(Debug, Error)]
pub enum PumpError {
    #[error(transparent)]
    DataPlane(#[from] DataPlaneError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("packet sink failed: {0}")]
    Sink(String),
}
