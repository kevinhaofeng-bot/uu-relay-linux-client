use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    AuthRequest, MessageType, PostAuthFrame, ProtocolError, decode_auth_response,
    decode_post_auth_frame, derive_proxy_key, encode_auth_request_gcm, encode_post_auth_frame,
};

const AUTH_RESPONSE_LIMIT: usize = 16 * 1024;
const POST_AUTH_PAYLOAD_LIMIT: usize = 0xfffc;
const FRAME_HEADER_LEN: usize = 3;
const REDACTED: &str = "<redacted>";

#[derive(Debug, Clone, Copy)]
pub struct SessionSettings {
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl SessionSettings {
    pub fn new(connect_timeout: Duration, io_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            io_timeout,
        }
    }
}

pub struct TcpRoomSession {
    stream: TcpStream,
    xor_key: Option<u8>,
    session_id: u32,
}

pub struct TcpRoomSender {
    stream: TcpStream,
    xor_key: Option<u8>,
}

pub struct TcpRoomReceiver {
    stream: TcpStream,
    xor_key: Option<u8>,
}

impl TcpRoomSession {
    pub fn connect(
        endpoint: SocketAddr,
        request: &AuthRequest,
        settings: SessionSettings,
    ) -> Result<Self, SessionError> {
        let mut stream = TcpStream::connect_timeout(&endpoint, settings.connect_timeout)?;
        stream.set_read_timeout(Some(settings.io_timeout))?;
        stream.set_write_timeout(Some(settings.io_timeout))?;
        stream.set_nodelay(true)?;

        let endpoint_text = endpoint.to_string();
        let key = Zeroizing::new(derive_proxy_key(&endpoint_text));
        let mut iv = Zeroizing::new([0_u8; 16]);
        getrandom::fill(iv.as_mut()).map_err(|_| SessionError::EntropyUnavailable)?;
        let auth_frame = encode_auth_request_gcm(request, &key, &iv)?;
        stream.write_all(&auth_frame)?;

        let response_frame = Zeroizing::new(read_frame(&mut stream, AUTH_RESPONSE_LIMIT)?);
        let response = decode_auth_response(&response_frame, &key)?;
        if response.result() != 0 {
            return Err(SessionError::AuthenticationRejected(response.result()));
        }
        let xor_key = response.xor_key_for_transport();
        let session_id = u32::try_from(response.session_id_for_transport())
            .ok()
            .filter(|session_id| *session_id != 0)
            .ok_or(SessionError::InvalidSessionId)?;
        Ok(Self {
            stream,
            xor_key,
            session_id,
        })
    }

    pub fn send_keepalive(&mut self) -> Result<(), SessionError> {
        send_frame(
            &mut self.stream,
            self.xor_key,
            MessageType::Keepalive,
            b"{}",
        )
    }

    pub fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        send_frame(
            &mut self.stream,
            self.xor_key,
            MessageType::Forward,
            payload,
        )
    }

    pub fn receive(&mut self) -> Result<PostAuthFrame, SessionError> {
        receive_frame(&mut self.stream, self.xor_key)
    }

    pub fn try_split(&self) -> Result<(TcpRoomSender, TcpRoomReceiver), SessionError> {
        Ok((
            TcpRoomSender {
                stream: self.stream.try_clone()?,
                xor_key: self.xor_key,
            },
            TcpRoomReceiver {
                stream: self.stream.try_clone()?,
                xor_key: self.xor_key,
            },
        ))
    }

    pub fn local_transport_address(&self) -> Result<SocketAddr, SessionError> {
        self.stream.local_addr().map_err(SessionError::Io)
    }

    pub fn remote_transport_address(&self) -> Result<SocketAddr, SessionError> {
        self.stream.peer_addr().map_err(SessionError::Io)
    }

    pub fn p2p_xor_key(&self) -> Option<u8> {
        self.xor_key.filter(|key| *key != 0)
    }

    pub fn p2p_session_id(&self) -> Option<u32> {
        (self.session_id != 0).then_some(self.session_id)
    }
}

impl TcpRoomSender {
    pub fn send_keepalive(&mut self) -> Result<(), SessionError> {
        send_frame(
            &mut self.stream,
            self.xor_key,
            MessageType::Keepalive,
            b"{}",
        )
    }

    pub fn send_forward_payload(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        send_frame(
            &mut self.stream,
            self.xor_key,
            MessageType::Forward,
            payload,
        )
    }
}

impl TcpRoomReceiver {
    pub fn receive(&mut self) -> Result<PostAuthFrame, SessionError> {
        receive_frame(&mut self.stream, self.xor_key)
    }
}

impl fmt::Debug for TcpRoomSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpRoomSession")
            .field("connected", &true)
            .field("xor_key", &self.xor_key.map(|_| REDACTED))
            .field("session_id", &REDACTED)
            .finish()
    }
}

impl Drop for TcpRoomSession {
    fn drop(&mut self) {
        self.xor_key.zeroize();
        self.session_id.zeroize();
    }
}

impl Drop for TcpRoomSender {
    fn drop(&mut self) {
        self.xor_key.zeroize();
    }
}

impl Drop for TcpRoomReceiver {
    fn drop(&mut self) {
        self.xor_key.zeroize();
    }
}

impl fmt::Debug for TcpRoomSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpRoomSender")
            .field("connected", &true)
            .field("xor_key", &self.xor_key.map(|_| REDACTED))
            .finish()
    }
}

impl fmt::Debug for TcpRoomReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpRoomReceiver")
            .field("connected", &true)
            .field("xor_key", &self.xor_key.map(|_| REDACTED))
            .finish()
    }
}

fn send_frame(
    stream: &mut TcpStream,
    xor_key: Option<u8>,
    message_type: MessageType,
    payload: &[u8],
) -> Result<(), SessionError> {
    let frame = encode_post_auth_frame(message_type, payload, xor_key)?;
    stream.write_all(&frame)?;
    Ok(())
}

fn receive_frame(
    stream: &mut TcpStream,
    xor_key: Option<u8>,
) -> Result<PostAuthFrame, SessionError> {
    let frame = read_frame(stream, POST_AUTH_PAYLOAD_LIMIT)?;
    decode_post_auth_frame(&frame, xor_key).map_err(SessionError::Protocol)
}

fn read_frame(stream: &mut TcpStream, payload_limit: usize) -> Result<Vec<u8>, SessionError> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let declared = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if declared > payload_limit {
        return Err(SessionError::FrameTooLarge {
            declared,
            limit: payload_limit,
        });
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + declared);
    frame.extend_from_slice(&header);
    frame.resize(FRAME_HEADER_LEN + declared, 0);
    stream.read_exact(&mut frame[FRAME_HEADER_LEN..])?;
    Ok(frame)
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("TCP room session I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("UU room authentication was rejected with result {0}")]
    AuthenticationRejected(i64),
    #[error("UU room authentication returned an invalid P2P session id")]
    InvalidSessionId,
    #[error("UU server frame declared {declared} bytes, exceeding limit {limit}")]
    FrameTooLarge { declared: usize, limit: usize },
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
}

impl SessionError {
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Self::Io(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )
        )
    }
}
