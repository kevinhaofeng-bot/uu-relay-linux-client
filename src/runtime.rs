use std::net::IpAddr;

use serde::Serialize;
use thiserror::Error;

use crate::bootstrap::JoinBootstrap;
use crate::config::ClientConfig;
use crate::session::{SessionError, SessionSettings, TcpRoomSession};
use crate::tun::{TunBackend, TunDevice, TunError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Stopped,
    Validated,
    DeviceReady,
    Connecting,
    Joined,
    Stopping,
    Failed,
}

pub trait RoomConnector {
    fn join(&mut self, config: &ClientConfig) -> Result<JoinAcknowledgement, ConnectorError>;

    fn disconnect(&mut self) {}
}

#[derive(Debug)]
pub struct JoinAcknowledgement {
    room_id: String,
    assigned_address: IpAddr,
    _authenticated_control_frame: AuthenticatedControlFrame,
}

impl JoinAcknowledgement {
    pub fn authenticated(room_id: impl Into<String>, assigned_address: IpAddr) -> Self {
        Self {
            room_id: room_id.into(),
            assigned_address,
            _authenticated_control_frame: AuthenticatedControlFrame,
        }
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn assigned_address(&self) -> IpAddr {
        self.assigned_address
    }
}

#[derive(Debug)]
struct AuthenticatedControlFrame;

pub struct UnrecoveredConnector;

impl RoomConnector for UnrecoveredConnector {
    fn join(&mut self, _config: &ClientConfig) -> Result<JoinAcknowledgement, ConnectorError> {
        Err(ConnectorError::ProtocolNotRecovered)
    }
}

pub struct RecoveredTcpConnector {
    bootstrap: JoinBootstrap,
    settings: SessionSettings,
    session: Option<TcpRoomSession>,
}

impl RecoveredTcpConnector {
    pub fn new(bootstrap: JoinBootstrap, settings: SessionSettings) -> Self {
        Self {
            bootstrap,
            settings,
            session: None,
        }
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    pub fn session_mut(&mut self) -> Option<&mut TcpRoomSession> {
        self.session.as_mut()
    }
}

impl RoomConnector for RecoveredTcpConnector {
    fn join(&mut self, config: &ClientConfig) -> Result<JoinAcknowledgement, ConnectorError> {
        if self.session.is_some() {
            return Err(ConnectorError::AlreadyJoined);
        }
        if self.bootstrap.room_id() != config.room_id() {
            return Err(ConnectorError::ConfigurationMismatch("room_id"));
        }
        let assigned_address = IpAddr::V4(self.bootstrap.client_lan_ip());
        if assigned_address != config.overlay_address() {
            return Err(ConnectorError::ConfigurationMismatch("overlay_address"));
        }

        let request = self.bootstrap.auth_request();
        let session =
            TcpRoomSession::connect(self.bootstrap.server_endpoint(), &request, self.settings)?;
        self.session = Some(session);
        Ok(JoinAcknowledgement::authenticated(
            self.bootstrap.room_id(),
            assigned_address,
        ))
    }

    fn disconnect(&mut self) {
        self.session.take();
    }
}

pub struct OverlayRuntime<B, C> {
    tun_backend: B,
    connector: C,
    device: Option<Box<dyn TunDevice>>,
    state: RuntimeState,
    history: Vec<RuntimeState>,
}

impl<B, C> OverlayRuntime<B, C>
where
    B: TunBackend,
    C: RoomConnector,
{
    pub fn new(tun_backend: B, connector: C) -> Self {
        Self {
            tun_backend,
            connector,
            device: None,
            state: RuntimeState::Stopped,
            history: vec![RuntimeState::Stopped],
        }
    }

    pub fn state(&self) -> RuntimeState {
        self.state
    }

    pub fn history(&self) -> &[RuntimeState] {
        &self.history
    }

    pub fn start(&mut self, config: &ClientConfig) -> Result<(), RuntimeError> {
        if self.state != RuntimeState::Stopped {
            return Err(RuntimeError::InvalidState(self.state));
        }
        self.transition(RuntimeState::Validated);

        let device = match self.tun_backend.create(config.overlay_address()) {
            Ok(device) => device,
            Err(error) => {
                self.transition(RuntimeState::Failed);
                return Err(RuntimeError::Tun(error));
            }
        };
        self.device = Some(device);
        self.transition(RuntimeState::DeviceReady);
        self.transition(RuntimeState::Connecting);

        let acknowledgement = match self.connector.join(config) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) => return self.fail_and_close(RuntimeError::Connector(error)),
        };
        if acknowledgement.room_id != config.room_id() {
            return self.fail_and_close(RuntimeError::RoomMismatch {
                expected: config.room_id().to_owned(),
                actual: acknowledgement.room_id,
            });
        }
        if acknowledgement.assigned_address != config.overlay_address() {
            return self.fail_and_close(RuntimeError::AddressMismatch {
                expected: config.overlay_address(),
                actual: acknowledgement.assigned_address,
            });
        }

        self.transition(RuntimeState::Joined);
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), RuntimeError> {
        if self.state == RuntimeState::Stopped {
            return Ok(());
        }
        self.transition(RuntimeState::Stopping);
        self.connector.disconnect();
        if let Some(mut device) = self.device.take()
            && let Err(error) = device.close()
        {
            self.transition(RuntimeState::Failed);
            return Err(RuntimeError::Tun(error));
        }
        self.transition(RuntimeState::Stopped);
        Ok(())
    }

    fn fail_and_close(&mut self, primary: RuntimeError) -> Result<(), RuntimeError> {
        self.connector.disconnect();
        let cleanup = self
            .device
            .take()
            .map(|mut device| device.close())
            .transpose();
        self.transition(RuntimeState::Failed);
        match cleanup {
            Ok(_) => Err(primary),
            Err(cleanup) => Err(RuntimeError::Cleanup {
                primary: Box::new(primary),
                cleanup,
            }),
        }
    }

    fn transition(&mut self, state: RuntimeState) {
        self.state = state;
        self.history.push(state);
    }
}

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("UU LAN Play protocol has not been recovered from a verified dynamic fixture")]
    ProtocolNotRecovered,
    #[error("room connector configuration does not match bootstrap field {0}")]
    ConfigurationMismatch(&'static str),
    #[error("room connector is already joined")]
    AlreadyJoined,
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("room connector rejected the join: {0}")]
    Rejected(String),
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime cannot start from state {0:?}")]
    InvalidState(RuntimeState),
    #[error(transparent)]
    Tun(TunError),
    #[error(transparent)]
    Connector(ConnectorError),
    #[error("room acknowledgement mismatch: expected {expected}, got {actual}")]
    RoomMismatch { expected: String, actual: String },
    #[error("overlay address mismatch: expected {expected}, got {actual}")]
    AddressMismatch { expected: IpAddr, actual: IpAddr },
    #[error("runtime failed with {primary}; TUN cleanup also failed: {cleanup}")]
    Cleanup {
        primary: Box<RuntimeError>,
        cleanup: TunError,
    },
}
