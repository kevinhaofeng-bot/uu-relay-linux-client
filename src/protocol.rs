use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::consts::U16;
use aes_gcm::{AesGcm, Nonce, Tag};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const AUTH_HEADER_LEN: usize = 4;
const POST_AUTH_HEADER_LEN: usize = 3;
const AES_BLOCK_LEN: usize = 16;
const GCM_IV_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
const MAX_POST_AUTH_PAYLOAD: usize = 0xfffc;
const REDACTED: &str = "<redacted>";
const FORWARD_LEGACY_HEADER_LEN: usize = 5;
const FORWARD_V2_PREFIX_LEN: usize = 6;
const FORWARD_V2_IPV4_HEADER_LEN: usize = 12;
const FORWARD_V2_IPV6_HEADER_LEN: usize = 24;

type Aes128Gcm16 = AesGcm<Aes128, U16>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    AuthRequest = 0,
    AuthResponse = 1,
    Keepalive = 2,
    Forward = 64,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AuthRequest),
            1 => Ok(Self::AuthResponse),
            2 => Ok(Self::Keepalive),
            64 => Ok(Self::Forward),
            other => Err(ProtocolError::UnsupportedMessageType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionMethod {
    Plaintext = 0,
    Aes128Ecb = 1,
    Aes128Gcm = 2,
}

impl TryFrom<u8> for EncryptionMethod {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Plaintext),
            1 => Ok(Self::Aes128Ecb),
            2 => Ok(Self::Aes128Gcm),
            other => Err(ProtocolError::UnsupportedEncryptionMethod(other)),
        }
    }
}

#[derive(Serialize)]
pub struct AuthRequest {
    room_id: String,
    password: String,
    client_id: String,
    client_lan_ip: String,
    encrypt_on: u8,
}

impl AuthRequest {
    pub fn new(
        room_id: impl Into<String>,
        password: impl Into<String>,
        client_id: impl Into<String>,
        client_lan_ip: impl Into<String>,
    ) -> Self {
        Self {
            room_id: room_id.into(),
            password: password.into(),
            client_id: client_id.into(),
            client_lan_ip: client_lan_ip.into(),
            encrypt_on: 1,
        }
    }

    fn to_json(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(ProtocolError::SerializeAuthJson)
    }
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthRequest")
            .field("room_id", &self.room_id)
            .field("password", &REDACTED)
            .field("client_id", &REDACTED)
            .field("client_lan_ip", &self.client_lan_ip)
            .field("encrypt_on", &self.encrypt_on)
            .finish()
    }
}

impl Drop for AuthRequest {
    fn drop(&mut self) {
        self.password.zeroize();
        self.client_id.zeroize();
    }
}

pub struct AuthResponse {
    result: i64,
    session_id: i64,
    xor_key: Option<u8>,
}

impl AuthResponse {
    pub fn result(&self) -> i64 {
        self.result
    }

    pub fn session_id_for_transport(&self) -> i64 {
        self.session_id
    }

    pub fn xor_key_for_transport(&self) -> Option<u8> {
        self.xor_key
    }
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthResponse")
            .field("result", &self.result)
            .field("session_id", &REDACTED)
            .field("xor_key", &self.xor_key.map(|_| REDACTED))
            .finish()
    }
}

impl Drop for AuthResponse {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.xor_key.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PostAuthFrame {
    message_type: MessageType,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardVersion {
    Legacy,
    Addressed,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ForwardPacket<'a> {
    version: ForwardVersion,
    packet_id: u32,
    transport_address: Option<SocketAddr>,
    ip_packet: &'a [u8],
}

impl<'a> ForwardPacket<'a> {
    pub fn version(&self) -> ForwardVersion {
        self.version
    }

    pub fn packet_id(&self) -> u32 {
        self.packet_id
    }

    pub fn transport_address(&self) -> Option<SocketAddr> {
        self.transport_address
    }

    pub fn ip_packet(&self) -> &'a [u8] {
        self.ip_packet
    }
}

impl PostAuthFrame {
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub fn derive_proxy_key(endpoint: &str) -> [u8; AES_BLOCK_LEN] {
    let bytes = endpoint.as_bytes();
    if bytes.len() >= AES_BLOCK_LEN {
        let mut key = [0_u8; AES_BLOCK_LEN];
        key.copy_from_slice(&bytes[..AES_BLOCK_LEN]);
        key
    } else {
        Md5::digest(bytes).into()
    }
}

pub fn encode_auth_request_gcm(
    request: &AuthRequest,
    key: &[u8; AES_BLOCK_LEN],
    iv: &[u8; GCM_IV_LEN],
) -> Result<Vec<u8>, ProtocolError> {
    let mut ciphertext = Zeroizing::new(request.to_json()?);
    let cipher = Aes128Gcm16::new_from_slice(key).map_err(|_| ProtocolError::InvalidKey)?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<U16>::from_slice(iv), b"", &mut ciphertext)
        .map_err(|_| ProtocolError::EncryptionFailed)?;

    let encrypted_len = 1 + GCM_IV_LEN + ciphertext.len() + GCM_TAG_LEN;
    let payload_len = encrypted_len
        .checked_add(1)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(ProtocolError::PayloadTooLarge(encrypted_len))?;
    let mut frame = Vec::with_capacity(AUTH_HEADER_LEN + encrypted_len);
    frame.push(MessageType::AuthRequest as u8);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(EncryptionMethod::Aes128Gcm as u8);
    frame.push(GCM_IV_LEN as u8);
    frame.extend_from_slice(iv);
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&tag);
    Ok(frame)
}

pub fn decode_auth_response(
    frame: &[u8],
    key: &[u8; AES_BLOCK_LEN],
) -> Result<AuthResponse, ProtocolError> {
    if frame.len() < AUTH_HEADER_LEN {
        return Err(ProtocolError::FrameTooShort {
            minimum: AUTH_HEADER_LEN,
            actual: frame.len(),
        });
    }
    let message_type = MessageType::try_from(frame[0])?;
    if message_type != MessageType::AuthResponse {
        return Err(ProtocolError::UnexpectedMessageType {
            expected: MessageType::AuthResponse,
            actual: message_type,
        });
    }
    let declared = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
    if declared <= 1 || declared + POST_AUTH_HEADER_LEN != frame.len() {
        return Err(ProtocolError::LengthMismatch {
            declared,
            actual: frame.len().saturating_sub(POST_AUTH_HEADER_LEN),
        });
    }

    let method = EncryptionMethod::try_from(frame[3])?;
    let plaintext = Zeroizing::new(match method {
        EncryptionMethod::Plaintext => frame[AUTH_HEADER_LEN..].to_vec(),
        EncryptionMethod::Aes128Ecb => decrypt_ecb(&frame[AUTH_HEADER_LEN..], key)?,
        EncryptionMethod::Aes128Gcm => decrypt_gcm(&frame[AUTH_HEADER_LEN..], key)?,
    });
    let wire: WireAuthResponse = serde_json::from_slice(&plaintext)
        .map_err(|error| ProtocolError::InvalidAuthJson(error.to_string()))?;

    let xor_key = if wire.result == 0 && wire.encrypt_method == "XOR" {
        wire.encrypt_key.as_bytes().first().copied()
    } else {
        None
    };
    let response = AuthResponse {
        result: wire.result,
        session_id: wire.session_id,
        xor_key,
    };
    Ok(response)
}

pub fn encode_post_auth_frame(
    message_type: MessageType,
    payload: &[u8],
    xor_key: Option<u8>,
) -> Result<Vec<u8>, ProtocolError> {
    if !matches!(message_type, MessageType::Keepalive | MessageType::Forward) {
        return Err(ProtocolError::InvalidPostAuthMessageType(message_type));
    }
    if payload.len() > MAX_POST_AUTH_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(payload.len()));
    }
    let length =
        u16::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(POST_AUTH_HEADER_LEN + payload.len());
    frame.push(message_type as u8);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    apply_xor(&mut frame[POST_AUTH_HEADER_LEN..], xor_key);
    Ok(frame)
}

pub fn decode_post_auth_frame(
    frame: &[u8],
    xor_key: Option<u8>,
) -> Result<PostAuthFrame, ProtocolError> {
    if frame.len() < POST_AUTH_HEADER_LEN {
        return Err(ProtocolError::FrameTooShort {
            minimum: POST_AUTH_HEADER_LEN,
            actual: frame.len(),
        });
    }
    let message_type = MessageType::try_from(frame[0])?;
    if !matches!(message_type, MessageType::Keepalive | MessageType::Forward) {
        return Err(ProtocolError::InvalidPostAuthMessageType(message_type));
    }
    let declared = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
    let actual = frame.len() - POST_AUTH_HEADER_LEN;
    if declared != actual {
        return Err(ProtocolError::LengthMismatch { declared, actual });
    }
    if declared > MAX_POST_AUTH_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(declared));
    }
    let mut payload = frame[POST_AUTH_HEADER_LEN..].to_vec();
    apply_xor(&mut payload, xor_key);
    Ok(PostAuthFrame {
        message_type,
        payload,
    })
}

pub fn encode_forward_v2(
    packet_id: u32,
    transport_address: SocketAddr,
    ip_packet: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    validate_inner_ip_packet(ip_packet)?;
    let header_len = if transport_address.is_ipv4() {
        FORWARD_V2_IPV4_HEADER_LEN
    } else {
        FORWARD_V2_IPV6_HEADER_LEN
    };
    let payload_len = header_len
        .checked_add(ip_packet.len())
        .ok_or(ProtocolError::PayloadTooLarge(usize::MAX))?;
    if payload_len > MAX_POST_AUTH_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }

    let mut payload = Vec::with_capacity(payload_len);
    payload.push(2);
    payload.extend_from_slice(&packet_id.to_be_bytes());
    match transport_address {
        SocketAddr::V4(address) => {
            payload.push(1);
            payload.extend_from_slice(&address.ip().octets());
            payload.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            payload.push(4);
            payload.extend_from_slice(&address.ip().octets());
            payload.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    payload.extend_from_slice(ip_packet);
    Ok(payload)
}

pub fn encode_forward_legacy(packet_id: u32, ip_packet: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    validate_inner_ip_packet(ip_packet)?;
    let payload_len = FORWARD_LEGACY_HEADER_LEN
        .checked_add(ip_packet.len())
        .ok_or(ProtocolError::PayloadTooLarge(usize::MAX))?;
    if payload_len > MAX_POST_AUTH_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }
    let mut payload = Vec::with_capacity(payload_len);
    payload.push(1);
    payload.extend_from_slice(&packet_id.to_be_bytes());
    payload.extend_from_slice(ip_packet);
    Ok(payload)
}

pub fn decode_forward_payload(payload: &[u8]) -> Result<ForwardPacket<'_>, ProtocolError> {
    if payload.len() < FORWARD_LEGACY_HEADER_LEN {
        return Err(ProtocolError::FrameTooShort {
            minimum: FORWARD_LEGACY_HEADER_LEN,
            actual: payload.len(),
        });
    }
    let packet_id = u32::from_be_bytes(payload[1..5].try_into().expect("length checked above"));
    let (version, transport_address, ip_packet) = match payload[0] {
        1 => (
            ForwardVersion::Legacy,
            None,
            &payload[FORWARD_LEGACY_HEADER_LEN..],
        ),
        2 => decode_addressed_forward_payload(payload)?,
        other => return Err(ProtocolError::UnsupportedForwardVersion(other)),
    };
    validate_inner_ip_packet(ip_packet)?;
    Ok(ForwardPacket {
        version,
        packet_id,
        transport_address,
        ip_packet,
    })
}

fn decode_addressed_forward_payload(
    payload: &[u8],
) -> Result<(ForwardVersion, Option<SocketAddr>, &[u8]), ProtocolError> {
    if payload.len() < FORWARD_V2_PREFIX_LEN {
        return Err(ProtocolError::FrameTooShort {
            minimum: FORWARD_V2_PREFIX_LEN,
            actual: payload.len(),
        });
    }
    let (transport_address, header_len) = match payload[5] {
        1 => {
            ensure_forward_header(payload, FORWARD_V2_IPV4_HEADER_LEN)?;
            let ip = Ipv4Addr::new(payload[6], payload[7], payload[8], payload[9]);
            let port = u16::from_be_bytes([payload[10], payload[11]]);
            (
                SocketAddr::new(IpAddr::V4(ip), port),
                FORWARD_V2_IPV4_HEADER_LEN,
            )
        }
        4 => {
            ensure_forward_header(payload, FORWARD_V2_IPV6_HEADER_LEN)?;
            let octets: [u8; 16] = payload[6..22]
                .try_into()
                .expect("length checked before conversion");
            let port = u16::from_be_bytes([payload[22], payload[23]]);
            (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                FORWARD_V2_IPV6_HEADER_LEN,
            )
        }
        other => return Err(ProtocolError::UnsupportedForwardAddressType(other)),
    };
    Ok((
        ForwardVersion::Addressed,
        Some(transport_address),
        &payload[header_len..],
    ))
}

fn ensure_forward_header(payload: &[u8], minimum: usize) -> Result<(), ProtocolError> {
    if payload.len() < minimum {
        return Err(ProtocolError::FrameTooShort {
            minimum,
            actual: payload.len(),
        });
    }
    Ok(())
}

fn validate_inner_ip_packet(ip_packet: &[u8]) -> Result<(), ProtocolError> {
    let version = ip_packet.first().map(|byte| byte >> 4);
    let minimum = match version {
        Some(4) => 20,
        Some(6) => 40,
        Some(other) => return Err(ProtocolError::UnsupportedIpVersion(other)),
        None => 20,
    };
    if ip_packet.len() < minimum {
        return Err(ProtocolError::InnerPacketTooShort {
            minimum,
            actual: ip_packet.len(),
        });
    }
    Ok(())
}

fn apply_xor(payload: &mut [u8], key: Option<u8>) {
    if let Some(key) = key.filter(|key| *key != 0) {
        for byte in payload {
            *byte ^= key;
        }
    }
}

fn decrypt_gcm(payload: &[u8], key: &[u8; AES_BLOCK_LEN]) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() < 1 + GCM_IV_LEN + GCM_TAG_LEN || payload[0] as usize != GCM_IV_LEN {
        return Err(ProtocolError::InvalidGcmPayload);
    }
    let iv_end = 1 + GCM_IV_LEN;
    let tag_start = payload.len() - GCM_TAG_LEN;
    let mut plaintext = payload[iv_end..tag_start].to_vec();
    let cipher = Aes128Gcm16::new_from_slice(key).map_err(|_| ProtocolError::InvalidKey)?;
    cipher
        .decrypt_in_place_detached(
            Nonce::<U16>::from_slice(&payload[1..iv_end]),
            b"",
            &mut plaintext,
            Tag::from_slice(&payload[tag_start..]),
        )
        .map_err(|_| ProtocolError::AuthenticationFailed)?;
    Ok(plaintext)
}

fn decrypt_ecb(payload: &[u8], key: &[u8; AES_BLOCK_LEN]) -> Result<Vec<u8>, ProtocolError> {
    if payload.is_empty() || !payload.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(ProtocolError::InvalidEcbPayload);
    }
    let cipher = Aes128::new_from_slice(key).map_err(|_| ProtocolError::InvalidKey)?;
    let mut plaintext = payload.to_vec();
    for block in plaintext.chunks_exact_mut(AES_BLOCK_LEN) {
        cipher.decrypt_block(block.into());
    }
    let padding = usize::from(*plaintext.last().ok_or(ProtocolError::InvalidEcbPadding)?);
    if padding == 0
        || padding > AES_BLOCK_LEN
        || plaintext[plaintext.len() - padding..]
            .iter()
            .any(|byte| usize::from(*byte) != padding)
    {
        plaintext.zeroize();
        return Err(ProtocolError::InvalidEcbPadding);
    }
    plaintext.truncate(plaintext.len() - padding);
    Ok(plaintext)
}

#[allow(dead_code)]
fn encrypt_ecb(payload: &[u8], key: &[u8; AES_BLOCK_LEN]) -> Result<Vec<u8>, ProtocolError> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| ProtocolError::InvalidKey)?;
    let padding = AES_BLOCK_LEN - (payload.len() % AES_BLOCK_LEN);
    let mut ciphertext = Vec::with_capacity(payload.len() + padding);
    ciphertext.extend_from_slice(payload);
    ciphertext.resize(payload.len() + padding, padding as u8);
    for block in ciphertext.chunks_exact_mut(AES_BLOCK_LEN) {
        cipher.encrypt_block(block.into());
    }
    Ok(ciphertext)
}

#[derive(Deserialize)]
struct WireAuthResponse {
    result: i64,
    #[serde(default)]
    session_id: i64,
    #[serde(default)]
    encrypt_method: String,
    #[serde(default)]
    encrypt_key: String,
}

impl Drop for WireAuthResponse {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.encrypt_method.zeroize();
        self.encrypt_key.zeroize();
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame is too short: expected at least {minimum} bytes, got {actual}")]
    FrameTooShort { minimum: usize, actual: usize },
    #[error("unsupported message type {0}")]
    UnsupportedMessageType(u8),
    #[error("unexpected message type {actual:?}; expected {expected:?}")]
    UnexpectedMessageType {
        expected: MessageType,
        actual: MessageType,
    },
    #[error("message type {0:?} is invalid after authentication")]
    InvalidPostAuthMessageType(MessageType),
    #[error("unsupported encryption method {0}")]
    UnsupportedEncryptionMethod(u8),
    #[error("frame length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("payload is too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("failed to serialize authentication request: {0}")]
    SerializeAuthJson(serde_json::Error),
    #[error("authentication response is not valid JSON: {0}")]
    InvalidAuthJson(String),
    #[error("invalid AES key")]
    InvalidKey,
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-GCM authentication failed")]
    AuthenticationFailed,
    #[error("invalid AES-GCM payload")]
    InvalidGcmPayload,
    #[error("invalid AES-ECB payload")]
    InvalidEcbPayload,
    #[error("invalid AES-ECB padding")]
    InvalidEcbPadding,
    #[error("unsupported forward payload version {0}")]
    UnsupportedForwardVersion(u8),
    #[error("unsupported forward transport address type {0}")]
    UnsupportedForwardAddressType(u8),
    #[error("unsupported inner IP version {0}")]
    UnsupportedIpVersion(u8),
    #[error("inner IP packet is too short: expected at least {minimum} bytes, got {actual}")]
    InnerPacketTooShort { minimum: usize, actual: usize },
}
