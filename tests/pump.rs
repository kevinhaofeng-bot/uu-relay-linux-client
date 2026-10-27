use std::net::Ipv4Addr;

use uu_linux_client::bootstrap::RoomMemberTable;
use uu_linux_client::protocol::{decode_forward_payload, encode_forward_v2};
use uu_linux_client::pump::{ForwardSink, InboundPump, OutboundPump, PacketSink, ReceiveOutcome};

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

#[derive(Default)]
struct CapturedForwards(Vec<Vec<u8>>);

impl ForwardSink for CapturedForwards {
    type Error = &'static str;

    fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        self.0.push(payload.to_vec());
        Ok(())
    }
}

#[derive(Default)]
struct CapturedPackets(Vec<Vec<u8>>);

impl PacketSink for CapturedPackets {
    type Error = &'static str;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        self.0.push(packet.to_vec());
        Ok(())
    }
}

#[test]
fn outbound_tun_packet_becomes_exact_type_64_payload() {
    let table = members();
    let mut pump = OutboundPump::new(Ipv4Addr::new(172, 19, 163, 2), "172.19.163.0/24", &table)
        .expect("outbound pump");
    let inner = packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 3),
    );
    let mut sink = CapturedForwards::default();

    assert_eq!(pump.forward(&inner, &mut sink).expect("forward"), 1);
    let decoded = decode_forward_payload(&sink.0[0]).expect("decode captured payload");
    assert_eq!(decoded.packet_id(), 1);
    assert_eq!(
        decoded.transport_address().unwrap().to_string(),
        "203.0.113.9:4014"
    );
    assert_eq!(decoded.ip_packet(), inner);
}

#[test]
fn inbound_duplicate_is_not_written_to_tun_twice() {
    let table = members();
    let mut pump = InboundPump::new(Ipv4Addr::new(172, 19, 163, 2), &table);
    let inner = packet(
        Ipv4Addr::new(172, 19, 163, 3),
        Ipv4Addr::new(172, 19, 163, 2),
    );
    let payload =
        encode_forward_v2(9, "203.0.113.9:4014".parse().unwrap(), &inner).expect("forward payload");
    let mut sink = CapturedPackets::default();

    assert_eq!(
        pump.inject(&payload, &mut sink).expect("first receive"),
        ReceiveOutcome::Injected
    );
    assert_eq!(
        pump.inject(&payload, &mut sink).expect("duplicate receive"),
        ReceiveOutcome::Duplicate
    );
    assert_eq!(sink.0, vec![inner]);
}

#[test]
fn sink_failures_are_propagated_without_false_success() {
    struct FailedSink;
    impl ForwardSink for FailedSink {
        type Error = &'static str;
        fn send_forward_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
            Err("fixture send failed")
        }
    }

    let table = members();
    let mut pump = OutboundPump::new(Ipv4Addr::new(172, 19, 163, 2), "172.19.163.0/24", &table)
        .expect("outbound pump");
    let inner = packet(
        Ipv4Addr::new(172, 19, 163, 2),
        Ipv4Addr::new(172, 19, 163, 3),
    );

    let error = pump.forward(&inner, &mut FailedSink).unwrap_err();
    assert!(error.to_string().contains("fixture send failed"));
}
