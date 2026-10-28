use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::AuthRequest;

const REDACTED: &str = "<redacted>";
const JOIN_ACTION: &str = "vlan_join_room";
const MEMBER_UPDATE_ACTION: &str = "update_member_info";

pub struct JoinBootstrap {
    server_endpoint: SocketAddr,
    user_id: String,
    client_lan_ip: Ipv4Addr,
    client_lan_net: String,
    room_id: String,
    password: String,
    acc: String,
}

impl JoinBootstrap {
    pub fn parse_bridge_request(
        input: &[u8],
        expected_room_id: &str,
    ) -> Result<Self, BootstrapError> {
        let input = Zeroizing::new(input.to_vec());
        validate_bridge_action(&input, JOIN_ACTION)?;
        let envelope: NativeBridgeEnvelope<JoinWire> =
            serde_json::from_slice(&input).map_err(|_| BootstrapError::InvalidJson)?;
        let data = envelope.data.ok_or(BootstrapError::MissingData)?;
        Self::from_wire(data, expected_room_id)
    }

    fn from_wire(data: JoinWire, expected_room_id: &str) -> Result<Self, BootstrapError> {
        if data.server_port == 0 {
            return Err(BootstrapError::InvalidField("server_port"));
        }
        if data.room_id != expected_room_id {
            return Err(BootstrapError::RoomMismatch {
                expected: expected_room_id.to_owned(),
                actual: data.room_id,
            });
        }
        let server_ip = data
            .server_ip
            .parse::<IpAddr>()
            .map_err(|_| BootstrapError::InvalidField("server_ip"))?;
        let client_lan_ip = data
            .client_lan_ip
            .parse::<Ipv4Addr>()
            .map_err(|_| BootstrapError::InvalidField("client_lan_ip"))?;
        if data.user_id.is_empty() {
            return Err(BootstrapError::InvalidField("user_id"));
        }
        if data.client_lan_net.is_empty() {
            return Err(BootstrapError::InvalidField("client_lan_net"));
        }
        if data.password.is_empty() {
            return Err(BootstrapError::InvalidField("password"));
        }
        if data.acc.is_empty() {
            return Err(BootstrapError::InvalidField("acc"));
        }
        Ok(Self {
            server_endpoint: SocketAddr::new(server_ip, data.server_port),
            user_id: data.user_id,
            client_lan_ip,
            client_lan_net: data.client_lan_net,
            room_id: data.room_id,
            password: data.password,
            acc: data.acc,
        })
    }

    pub fn server_endpoint(&self) -> SocketAddr {
        self.server_endpoint
    }

    pub fn client_lan_ip(&self) -> Ipv4Addr {
        self.client_lan_ip
    }

    pub fn client_lan_net(&self) -> &str {
        &self.client_lan_net
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn auth_request(&self) -> AuthRequest {
        AuthRequest::new(
            self.room_id.clone(),
            self.password.clone(),
            self.user_id.clone(),
            self.client_lan_ip.to_string(),
        )
    }
}

#[derive(Debug)]
pub struct OfficialRoomJoin {
    bootstrap: JoinBootstrap,
    members: RoomMemberTable,
    self_is_online: bool,
}

impl OfficialRoomJoin {
    pub fn parse_http_response(
        input: &[u8],
        expected_room_id: &str,
    ) -> Result<Self, BootstrapError> {
        let input = Zeroizing::new(input.to_vec());
        let envelope: ApiEnvelope<OfficialJoinDataWire> =
            serde_json::from_slice(&input).map_err(|_| BootstrapError::InvalidJson)?;
        if !is_official_api_success(envelope.code) {
            return Err(BootstrapError::ApiRejected(envelope.code));
        }
        let data = envelope.data.ok_or(BootstrapError::MissingData)?;
        if data.room.room_id != expected_room_id {
            return Err(BootstrapError::RoomMismatch {
                expected: expected_room_id.to_owned(),
                actual: data.room.room_id,
            });
        }

        let self_members: Vec<&OfficialMemberWire> = data
            .room
            .members
            .iter()
            .filter(|member| member.is_self)
            .collect();
        if self_members.len() != 1 {
            return Err(BootstrapError::AmbiguousSelfMember(self_members.len()));
        }
        let self_member = self_members[0];
        let self_is_online = self_member.member.is_online;

        let user_id = data.user.user_id.into_string();
        let client_id = match data.user.product.as_str() {
            "android" => format!("{user_id}@android"),
            _ => user_id,
        };
        let bootstrap = JoinBootstrap::from_wire(
            JoinWire {
                server_ip: self_member.member.server_ip.clone(),
                server_port: self_member.member.server_port,
                user_id: client_id,
                client_lan_ip: self_member.member.client_lan_ip.clone(),
                client_lan_net: data.app.client_lan_net,
                room_id: expected_room_id.to_owned(),
                password: data.room.password,
                acc: data.app.acc,
            },
            expected_room_id,
        )?;
        let members = RoomMemberTable::from_wire(
            data.room
                .members
                .into_iter()
                .filter(|member| !member.is_self)
                .map(|member| member.member),
        )?;

        Ok(Self {
            bootstrap,
            members,
            self_is_online,
        })
    }

    pub fn bootstrap(&self) -> &JoinBootstrap {
        &self.bootstrap
    }

    pub fn into_bootstrap(self) -> JoinBootstrap {
        self.bootstrap
    }

    pub fn members(&self) -> &RoomMemberTable {
        &self.members
    }

    pub fn self_is_online(&self) -> bool {
        self.self_is_online
    }

    pub fn into_parts(self) -> (JoinBootstrap, RoomMemberTable) {
        (self.bootstrap, self.members)
    }
}

impl fmt::Debug for JoinBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinBootstrap")
            .field("server_endpoint", &self.server_endpoint)
            .field("user_id", &REDACTED)
            .field("client_lan_ip", &self.client_lan_ip)
            .field("client_lan_net", &self.client_lan_net)
            .field("room_id", &self.room_id)
            .field("password", &REDACTED)
            .field("acc", &REDACTED)
            .finish()
    }
}

impl Drop for JoinBootstrap {
    fn drop(&mut self) {
        self.user_id.zeroize();
        self.password.zeroize();
        self.acc.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomMember {
    client_lan_ip: Ipv4Addr,
    transport_address: SocketAddr,
}

impl RoomMember {
    pub fn client_lan_ip(&self) -> Ipv4Addr {
        self.client_lan_ip
    }

    pub fn transport_address(&self) -> SocketAddr {
        self.transport_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomMemberTable {
    online: Vec<RoomMember>,
}

impl RoomMemberTable {
    pub fn parse_bridge_request(input: &[u8]) -> Result<Self, BootstrapError> {
        validate_bridge_action(input, MEMBER_UPDATE_ACTION)?;
        let envelope: NativeBridgeEnvelope<MemberDataWire> =
            serde_json::from_slice(input).map_err(|_| BootstrapError::InvalidJson)?;
        let data = envelope.data.ok_or(BootstrapError::MissingData)?;
        Self::from_wire(data.member_info)
    }

    fn from_wire(members: impl IntoIterator<Item = MemberWire>) -> Result<Self, BootstrapError> {
        let mut seen = HashSet::new();
        let mut online = Vec::new();
        for member in members.into_iter().filter(|member| member.is_online) {
            if member.server_port == 0 {
                return Err(BootstrapError::InvalidField("server_port"));
            }
            let client_lan_ip = member
                .client_lan_ip
                .parse::<Ipv4Addr>()
                .map_err(|_| BootstrapError::InvalidField("client_lan_ip"))?;
            if !seen.insert(client_lan_ip) {
                return Err(BootstrapError::DuplicateMember(client_lan_ip));
            }
            let server_ip = member
                .server_ip
                .parse::<IpAddr>()
                .map_err(|_| BootstrapError::InvalidField("server_ip"))?;
            online.push(RoomMember {
                client_lan_ip,
                transport_address: SocketAddr::new(server_ip, member.server_port),
            });
        }
        Ok(Self { online })
    }

    pub fn online(&self) -> &[RoomMember] {
        &self.online
    }
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    code: i64,
    data: Option<T>,
}

fn is_official_api_success(code: i64) -> bool {
    code <= 0 || code == 200
}

#[derive(Deserialize)]
struct NativeBridgeEnvelope<T> {
    data: Option<T>,
}

#[derive(Deserialize)]
struct NativeBridgeAction {
    action: String,
}

fn validate_bridge_action(input: &[u8], expected: &'static str) -> Result<(), BootstrapError> {
    let envelope: NativeBridgeAction =
        serde_json::from_slice(input).map_err(|_| BootstrapError::InvalidJson)?;
    if envelope.action != expected {
        return Err(BootstrapError::InvalidAction {
            expected,
            actual: envelope.action,
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct JoinWire {
    server_ip: String,
    server_port: u16,
    user_id: String,
    client_lan_ip: String,
    client_lan_net: String,
    room_id: String,
    password: String,
    acc: String,
}

#[derive(Deserialize)]
struct MemberDataWire {
    member_info: Vec<MemberWire>,
}

#[derive(Deserialize)]
struct MemberWire {
    is_online: bool,
    client_lan_ip: String,
    server_ip: String,
    server_port: u16,
}

#[derive(Deserialize)]
struct OfficialJoinDataWire {
    room: OfficialRoomWire,
    user: OfficialUserWire,
    app: OfficialAppWire,
}

#[derive(Deserialize)]
struct OfficialRoomWire {
    room_id: String,
    password: String,
    members: Vec<OfficialMemberWire>,
}

#[derive(Deserialize)]
struct OfficialUserWire {
    user_id: OfficialUserIdWire,
    #[serde(default)]
    product: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OfficialUserIdWire {
    Text(String),
    Unsigned(u64),
    Signed(i64),
}

impl OfficialUserIdWire {
    fn into_string(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Unsigned(value) => value.to_string(),
            Self::Signed(value) => value.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct OfficialAppWire {
    client_lan_net: String,
    acc: String,
}

#[derive(Deserialize)]
struct OfficialMemberWire {
    is_self: bool,
    #[serde(flatten)]
    member: MemberWire,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("UU bootstrap response is not valid JSON")]
    InvalidJson,
    #[error("UU bootstrap API rejected the request with code {0}")]
    ApiRejected(i64),
    #[error("UU bootstrap response has no data object")]
    MissingData,
    #[error("unexpected UU native action: expected {expected}, got {actual}")]
    InvalidAction {
        expected: &'static str,
        actual: String,
    },
    #[error("UU bootstrap field {0} is missing or invalid")]
    InvalidField(&'static str),
    #[error("UU bootstrap room mismatch: expected {expected}, got {actual}")]
    RoomMismatch { expected: String, actual: String },
    #[error("UU member table contains duplicate overlay address {0}")]
    DuplicateMember(Ipv4Addr),
    #[error("UU room response contains {0} self members; expected exactly one")]
    AmbiguousSelfMember(usize),
}

#[cfg(test)]
mod tests {
    use super::OfficialRoomJoin;

    #[test]
    fn android_room_identity_uses_the_native_client_id_suffix() {
        let input = br#"{
          "code":0,
          "data":{
            "room":{"room_id":"AB12345","password":"p","members":[
              {"is_self":true,"is_online":true,"client_lan_ip":"172.19.163.4","server_ip":"203.0.113.8","server_port":4003}
            ]},
            "user":{"user_id":1234567890,"product":"android"},
            "app":{"client_lan_net":"172.19.163.0/24","acc":"a"}
          }
        }"#;

        let joined = OfficialRoomJoin::parse_http_response(input, "AB12345")
            .expect("valid Android room response");

        assert_eq!(joined.bootstrap.user_id, "1234567890@android");
    }
}
