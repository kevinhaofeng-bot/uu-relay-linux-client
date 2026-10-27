use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use uu_linux_client::evidence::{EvidenceError, EvidenceManifest};

#[test]
fn official_manifest_records_the_recovered_join_room_contract() {
    let manifest = official_manifest();

    assert_eq!(manifest.product_version(), "6.16.1");
    assert_eq!(manifest.build(), "5251");
    assert_eq!(manifest.abi().join_room_magic(), 0x8631);
    assert_eq!(manifest.abi().minimum_config_bytes(), 0x490);
    assert_eq!(
        manifest.abi().exports().collect::<Vec<_>>(),
        vec![
            "is_wintun_in_use",
            "isblank",
            "join_room",
            "leave_room",
            "switch_game",
            "switch_room",
            "update_room_members",
        ]
    );

    let artifact = manifest
        .artifact("lanplay_tun.dll")
        .expect("known DLL evidence");
    assert_eq!(artifact.size(), 2_595_320);
    assert_eq!(
        artifact.sha256(),
        "26876faf8f84f0664d96b556bc9c203d2e8ae40e1035861c8c173c13991a58de"
    );
}

#[test]
fn artifact_verification_accepts_an_independently_hashed_file() {
    let path = unique_temp_path("uu-evidence-ok");
    fs::write(&path, b"lanplay-fixture").expect("write fixture");
    let manifest =
        manifest_for_fixture("12fe1780b85955ba4cd6db92d743fcfa4912a151f530114638921c6db8be2b8f");

    manifest
        .verify_artifact("fixture.bin", &path)
        .expect("matching evidence");

    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn artifact_verification_rejects_changed_bytes() {
    let path = unique_temp_path("uu-evidence-changed");
    fs::write(&path, b"changed-fixture").expect("write fixture");
    let manifest =
        manifest_for_fixture("12fe1780b85955ba4cd6db92d743fcfa4912a151f530114638921c6db8be2b8f");

    let result = manifest.verify_artifact("fixture.bin", &path);
    assert!(matches!(result, Err(EvidenceError::HashMismatch { .. })));

    fs::remove_file(path).expect("remove fixture");
}

#[test]
fn duplicate_or_missing_exports_are_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(&official_manifest_json()).expect("manifest JSON");
    let exports = value["abi"]["exports"]
        .as_array_mut()
        .expect("exports array");
    exports.pop();
    exports.push(serde_json::Value::String("join_room".to_owned()));

    let result = EvidenceManifest::from_json(&value.to_string());
    assert!(matches!(result, Err(EvidenceError::InvalidAbi(_))));
}

#[test]
fn wrong_join_room_magic_is_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_str(&official_manifest_json()).expect("manifest JSON");
    value["abi"]["join_room_magic"] = serde_json::Value::from(0x1234);

    let result = EvidenceManifest::from_json(&value.to_string());
    assert!(matches!(result, Err(EvidenceError::InvalidAbi(_))));
}

fn official_manifest() -> EvidenceManifest {
    EvidenceManifest::from_json(&official_manifest_json()).expect("valid official manifest")
}

fn official_manifest_json() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/windows-6.16.1-5251.json");
    fs::read_to_string(path).expect("read official manifest")
}

fn manifest_for_fixture(sha256: &str) -> EvidenceManifest {
    let json = format!(
        r#"{{
          "schema_version": 1,
          "product_version": "test",
          "build": "fixture",
          "artifacts": [{{
            "name": "fixture.bin",
            "size": 15,
            "sha256": "{sha256}"
          }}],
          "abi": {{
            "library": "lanplay_tun.dll",
            "calling_convention": "cdecl",
            "join_room_magic": 34353,
            "minimum_config_bytes": 1168,
            "exports": [
              "is_wintun_in_use", "isblank", "join_room", "leave_room",
              "switch_game", "switch_room", "update_room_members"
            ]
          }}
        }}"#
    );
    EvidenceManifest::from_json(&json).expect("valid fixture manifest")
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.bin", std::process::id()))
}
