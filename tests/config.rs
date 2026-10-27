use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use uu_linux_client::config::{ClientConfig, ConfigError};

const VALID_CONFIG: &str = r#"{
  "room_id": "AB12345",
  "client_id": "router-linux",
  "overlay_address": "172.19.163.2",
  "session_id": "session-id-secret",
  "session_token": "session-secret",
  "mobile": "mobile-secret",
  "room_password": "room-secret"
}"#;

#[test]
fn valid_config_parses_and_diagnostics_redact_secrets() {
    let config = ClientConfig::from_json(VALID_CONFIG).expect("valid config");

    assert_eq!(config.room_id(), "AB12345");
    assert_eq!(config.client_id(), "router-linux");
    assert_eq!(
        config.overlay_address(),
        IpAddr::V4(Ipv4Addr::new(172, 19, 163, 2))
    );

    let debug = format!("{config:?}");
    let diagnostics = serde_json::to_string(&config.diagnostics()).expect("diagnostics JSON");
    for output in [&debug, &diagnostics] {
        assert!(!output.contains("session-id-secret"));
        assert!(!output.contains("session-secret"));
        assert!(!output.contains("mobile-secret"));
        assert!(!output.contains("room-secret"));
    }
    assert!(diagnostics.contains("<redacted>"));
}

#[test]
fn existing_vlan_session_can_replace_expired_bridge_credentials() {
    let cookie_config = r#"{
      "room_id": "AB12345",
      "client_id": "router-linux",
      "overlay_address": "172.19.163.2",
      "vlan_session": "existing-cookie-secret"
    }"#;

    let config = ClientConfig::from_json(cookie_config).expect("session-cookie config");
    assert_eq!(
        config.vlan_session_for_api(),
        Some("existing-cookie-secret")
    );
    let debug = format!("{config:?}");
    let diagnostics = serde_json::to_string(&config.diagnostics()).expect("diagnostics JSON");

    assert!(!debug.contains("existing-cookie-secret"));
    assert!(!diagnostics.contains("existing-cookie-secret"));
    assert!(diagnostics.contains("<redacted>"));
}

#[test]
fn official_login_credentials_are_available_only_from_complete_private_config() {
    let config = ClientConfig::from_json(VALID_CONFIG).expect("valid config");
    let credentials = config
        .official_login_credentials()
        .expect("complete credentials");
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("session-id-secret"));
    assert!(!debug.contains("session-secret"));
    assert!(!debug.contains("mobile-secret"));

    let missing = VALID_CONFIG.replace("\n  \"session_id\": \"session-id-secret\",", "");
    let incomplete = ClientConfig::from_json(&missing).expect("check can parse incomplete config");
    assert!(matches!(
        incomplete.official_login_credentials(),
        Err(ConfigError::MissingSessionId)
    ));
}

#[test]
fn malformed_room_id_is_rejected() {
    let invalid = VALID_CONFIG.replace("AB12345", "not-a-room");

    assert!(matches!(
        ClientConfig::from_json(&invalid),
        Err(ConfigError::InvalidRoomId(value)) if value == "not-a-room"
    ));
}

#[test]
fn unspecified_overlay_address_is_rejected() {
    let invalid = VALID_CONFIG.replace("172.19.163.2", "0.0.0.0");

    assert!(matches!(
        ClientConfig::from_json(&invalid),
        Err(ConfigError::InvalidOverlayAddress(value)) if value == "0.0.0.0"
    ));
}

#[cfg(unix)]
#[test]
fn secret_config_file_must_not_be_group_or_world_accessible() {
    use std::os::unix::fs::PermissionsExt;

    let path = unique_temp_path("uu-config");
    fs::write(&path, VALID_CONFIG).expect("write fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set insecure mode");

    let insecure = ClientConfig::load(&path);
    assert!(matches!(
        insecure,
        Err(ConfigError::InsecurePermissions { mode: 0o644, .. })
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set secure mode");
    let secure = ClientConfig::load(&path).expect("load secure config");
    assert_eq!(secure.room_id(), "AB12345");

    fs::remove_file(path).expect("remove fixture");
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.json", std::process::id()))
}
