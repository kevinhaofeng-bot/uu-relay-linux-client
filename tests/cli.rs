use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn check_emits_valid_json_without_secrets() {
    let config = write_private_fixture(
        "config",
        r#"{
          "room_id": "AB12345",
          "client_id": "router-linux",
          "overlay_address": "172.19.163.2",
          "session_token": "never-print-session",
          "room_password": "never-print-password"
        }"#,
    );

    let output = run(&["check", "--config", path_arg(&config)]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(value["ok"], true);
    assert_eq!(value["config"]["room_id"], "AB12345");
    assert_eq!(value["config"]["session_token"], "<redacted>");
    assert!(!combined(&output).contains("never-print-session"));
    assert!(!combined(&output).contains("never-print-password"));

    fs::remove_file(config).expect("remove config");
}

#[test]
fn verify_evidence_returns_nonzero_json_for_changed_file() {
    let artifact = write_private_fixture("artifact", "changed-fixture");
    let manifest = write_private_fixture("manifest", &fixture_manifest());

    let output = run(&[
        "verify-evidence",
        "--manifest",
        path_arg(&manifest),
        "--artifact",
        "fixture.bin",
        "--path",
        path_arg(&artifact),
    ]);

    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(value["ok"], false);
    assert_eq!(value["code"], "evidence_mismatch");

    fs::remove_file(artifact).expect("remove artifact");
    fs::remove_file(manifest).expect("remove manifest");
}

#[test]
fn run_requires_complete_official_credentials_before_touching_network_or_tun() {
    let config = write_private_fixture(
        "config-run",
        r#"{
          "room_id": "AB12345",
          "client_id": "router-linux",
          "overlay_address": "172.19.163.2",
          "session_token": "never-print-run-token"
        }"#,
    );

    let output = run(&["run", "--config", path_arg(&config), "--interface", "uu0"]);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(value["ok"], false);
    assert_eq!(value["code"], "credentials_missing");
    assert_eq!(value["state"], "stopped");
    assert!(!combined(&output).contains("never-print-run-token"));

    fs::remove_file(config).expect("remove config");
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uu-linux-client"))
        .args(args)
        .output()
        .expect("run uu-linux-client")
}

fn write_private_fixture(prefix: &str, contents: &str) -> PathBuf {
    let path = unique_temp_path(prefix);
    fs::write(&path, contents).expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set fixture mode");
    }
    path
}

fn fixture_manifest() -> String {
    r#"{
      "schema_version": 1,
      "product_version": "test",
      "build": "fixture",
      "artifacts": [{
        "name": "fixture.bin",
        "size": 15,
        "sha256": "12fe1780b85955ba4cd6db92d743fcfa4912a151f530114638921c6db8be2b8f"
      }],
      "abi": {
        "library": "lanplay_tun.dll",
        "calling_convention": "cdecl",
        "join_room_magic": 34353,
        "minimum_config_bytes": 1168,
        "exports": [
          "is_wintun_in_use", "isblank", "join_room", "leave_room",
          "switch_game", "switch_room", "update_room_members"
        ]
      }
    }"#
    .to_owned()
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("UTF-8 temp path")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.json", std::process::id()))
}
