use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use uu_linux_client::config::ClientConfig;
use uu_linux_client::runtime::{
    ConnectorError, JoinAcknowledgement, OverlayRuntime, RoomConnector, RuntimeError, RuntimeState,
};
use uu_linux_client::tun::{TunBackend, TunDevice, TunError};

#[test]
fn authenticated_matching_ack_is_the_only_path_to_joined() {
    let closed = Arc::new(AtomicBool::new(false));
    let disconnected = Arc::new(AtomicBool::new(false));
    let tun = FakeTunBackend::new(closed.clone());
    let connector = FixedConnector::success_with_disconnect(
        JoinAcknowledgement::authenticated("AB12345", IpAddr::V4(Ipv4Addr::new(172, 19, 163, 2))),
        disconnected.clone(),
    );
    let mut runtime = OverlayRuntime::new(tun, connector);

    runtime.start(&config()).expect("verified room join");

    assert_eq!(runtime.state(), RuntimeState::Joined);
    assert_eq!(
        runtime.history(),
        [
            RuntimeState::Stopped,
            RuntimeState::Validated,
            RuntimeState::DeviceReady,
            RuntimeState::Connecting,
            RuntimeState::Joined,
        ]
    );
    assert!(!closed.load(Ordering::SeqCst));

    runtime.shutdown().expect("clean shutdown");
    assert!(closed.load(Ordering::SeqCst));
    assert!(disconnected.load(Ordering::SeqCst));
    assert_eq!(runtime.state(), RuntimeState::Stopped);
}

#[test]
fn creating_a_tun_device_cannot_hide_an_unrecovered_protocol() {
    let closed = Arc::new(AtomicBool::new(false));
    let tun = FakeTunBackend::new(closed.clone());
    let mut runtime = OverlayRuntime::new(tun, uu_linux_client::runtime::UnrecoveredConnector);

    let result = runtime.start(&config());

    assert!(matches!(
        result,
        Err(RuntimeError::Connector(
            ConnectorError::ProtocolNotRecovered
        ))
    ));
    assert_eq!(runtime.state(), RuntimeState::Failed);
    assert!(!runtime.history().contains(&RuntimeState::Joined));
    assert!(closed.load(Ordering::SeqCst));
}

#[test]
fn room_mismatch_rejects_ack_and_closes_the_device() {
    let closed = Arc::new(AtomicBool::new(false));
    let disconnected = Arc::new(AtomicBool::new(false));
    let tun = FakeTunBackend::new(closed.clone());
    let connector = FixedConnector::success_with_disconnect(
        JoinAcknowledgement::authenticated("ZZ99999", IpAddr::V4(Ipv4Addr::new(172, 19, 163, 2))),
        disconnected.clone(),
    );
    let mut runtime = OverlayRuntime::new(tun, connector);

    let result = runtime.start(&config());

    assert!(matches!(result, Err(RuntimeError::RoomMismatch { .. })));
    assert_eq!(runtime.state(), RuntimeState::Failed);
    assert!(closed.load(Ordering::SeqCst));
    assert!(disconnected.load(Ordering::SeqCst));
}

#[test]
fn address_mismatch_rejects_ack_and_closes_the_device() {
    let closed = Arc::new(AtomicBool::new(false));
    let tun = FakeTunBackend::new(closed.clone());
    let connector = FixedConnector::success(JoinAcknowledgement::authenticated(
        "AB12345",
        IpAddr::V4(Ipv4Addr::new(172, 19, 163, 99)),
    ));
    let mut runtime = OverlayRuntime::new(tun, connector);

    let result = runtime.start(&config());

    assert!(matches!(result, Err(RuntimeError::AddressMismatch { .. })));
    assert_eq!(runtime.state(), RuntimeState::Failed);
    assert!(closed.load(Ordering::SeqCst));
}

#[test]
fn shutdown_cleanup_failure_transitions_to_failed() {
    let connector = FixedConnector::success(JoinAcknowledgement::authenticated(
        "AB12345",
        IpAddr::V4(Ipv4Addr::new(172, 19, 163, 2)),
    ));
    let mut runtime = OverlayRuntime::new(FailingCloseTunBackend, connector);
    runtime.start(&config()).expect("verified room join");

    let result = runtime.shutdown();

    assert!(matches!(result, Err(RuntimeError::Tun(_))));
    assert_eq!(runtime.state(), RuntimeState::Failed);
    assert_eq!(
        runtime.history()[runtime.history().len() - 2..],
        [RuntimeState::Stopping, RuntimeState::Failed]
    );
}

fn config() -> ClientConfig {
    ClientConfig::from_json(
        r#"{
          "room_id": "AB12345",
          "client_id": "router-linux",
          "overlay_address": "172.19.163.2",
          "session_token": "test-only-token"
        }"#,
    )
    .expect("valid test config")
}

struct FakeTunBackend {
    closed: Arc<AtomicBool>,
}

impl FakeTunBackend {
    fn new(closed: Arc<AtomicBool>) -> Self {
        Self { closed }
    }
}

impl TunBackend for FakeTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(FakeTunDevice {
            closed: self.closed.clone(),
        }))
    }
}

struct FakeTunDevice {
    closed: Arc<AtomicBool>,
}

impl TunDevice for FakeTunDevice {
    fn close(&mut self) -> Result<(), TunError> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingCloseTunBackend;

impl TunBackend for FailingCloseTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(FailingCloseTunDevice))
    }
}

struct FailingCloseTunDevice;

impl TunDevice for FailingCloseTunDevice {
    fn close(&mut self) -> Result<(), TunError> {
        Err(TunError::Operation("fixture close failure".to_owned()))
    }
}

struct FixedConnector {
    result: Option<Result<JoinAcknowledgement, ConnectorError>>,
    disconnected: Option<Arc<AtomicBool>>,
}

impl FixedConnector {
    fn success(ack: JoinAcknowledgement) -> Self {
        Self {
            result: Some(Ok(ack)),
            disconnected: None,
        }
    }

    fn success_with_disconnect(ack: JoinAcknowledgement, disconnected: Arc<AtomicBool>) -> Self {
        Self {
            result: Some(Ok(ack)),
            disconnected: Some(disconnected),
        }
    }
}

impl RoomConnector for FixedConnector {
    fn join(&mut self, _config: &ClientConfig) -> Result<JoinAcknowledgement, ConnectorError> {
        self.result.take().expect("join called once")
    }

    fn disconnect(&mut self) {
        if let Some(disconnected) = &self.disconnected {
            disconnected.store(true, Ordering::SeqCst);
        }
    }
}
