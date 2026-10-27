use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const REQUIRED_EXPORTS: [&str; 7] = [
    "is_wintun_in_use",
    "isblank",
    "join_room",
    "leave_room",
    "switch_game",
    "switch_room",
    "update_room_members",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    schema_version: u32,
    product_version: String,
    build: String,
    artifacts: Vec<ArtifactEvidence>,
    abi: AbiContract,
}

impl EvidenceManifest {
    pub fn from_json(input: &str) -> Result<Self, EvidenceError> {
        let manifest: Self = serde_json::from_str(input).map_err(EvidenceError::InvalidJson)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    pub fn build(&self) -> &str {
        &self.build
    }

    pub fn abi(&self) -> &AbiContract {
        &self.abi
    }

    pub fn artifact(&self, name: &str) -> Option<&ArtifactEvidence> {
        self.artifacts.iter().find(|artifact| artifact.name == name)
    }

    pub fn verify_artifact(&self, name: &str, path: impl AsRef<Path>) -> Result<(), EvidenceError> {
        let expected = self
            .artifact(name)
            .ok_or_else(|| EvidenceError::UnknownArtifact(name.to_owned()))?;
        let path = path.as_ref();
        let mut file = File::open(path).map_err(EvidenceError::Io)?;
        let actual_size = file.metadata().map_err(EvidenceError::Io)?.len();
        if actual_size != expected.size {
            return Err(EvidenceError::SizeMismatch {
                path: path.to_path_buf(),
                expected: expected.size,
                actual: actual_size,
            });
        }

        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(EvidenceError::Io)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected.sha256 {
            return Err(EvidenceError::HashMismatch {
                path: path.to_path_buf(),
                expected: expected.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != 1 {
            return Err(EvidenceError::UnsupportedSchema(self.schema_version));
        }
        let mut artifact_names = HashSet::new();
        for artifact in &self.artifacts {
            if !artifact_names.insert(&artifact.name) {
                return Err(EvidenceError::InvalidArtifact(format!(
                    "duplicate artifact {}",
                    artifact.name
                )));
            }
            if artifact.sha256.len() != 64
                || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(EvidenceError::InvalidArtifact(format!(
                    "invalid SHA-256 for {}",
                    artifact.name
                )));
            }
        }
        self.abi.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    name: String,
    size: u64,
    sha256: String,
}

impl ArtifactEvidence {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbiContract {
    library: String,
    calling_convention: String,
    join_room_magic: u16,
    minimum_config_bytes: usize,
    exports: Vec<String>,
}

impl AbiContract {
    pub fn join_room_magic(&self) -> u16 {
        self.join_room_magic
    }

    pub fn minimum_config_bytes(&self) -> usize {
        self.minimum_config_bytes
    }

    pub fn exports(&self) -> impl ExactSizeIterator<Item = &str> {
        self.exports.iter().map(String::as_str)
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        if self.library != "lanplay_tun.dll" || self.calling_convention != "cdecl" {
            return Err(EvidenceError::InvalidAbi(
                "unexpected library or calling convention".to_owned(),
            ));
        }
        if self.join_room_magic != 0x8631 {
            return Err(EvidenceError::InvalidAbi(format!(
                "unexpected join_room magic 0x{:04x}",
                self.join_room_magic
            )));
        }
        if self.minimum_config_bytes < 0x490 {
            return Err(EvidenceError::InvalidAbi(format!(
                "configuration boundary {} is smaller than observed access 0x48c",
                self.minimum_config_bytes
            )));
        }
        let unique: HashSet<_> = self.exports.iter().map(String::as_str).collect();
        let required: HashSet<_> = REQUIRED_EXPORTS.into_iter().collect();
        if unique != required || unique.len() != self.exports.len() {
            return Err(EvidenceError::InvalidAbi(
                "export set does not match recovered seven-entry ABI".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence is not valid JSON: {0}")]
    InvalidJson(serde_json::Error),
    #[error("unsupported evidence schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid artifact evidence: {0}")]
    InvalidArtifact(String),
    #[error("invalid recovered ABI: {0}")]
    InvalidAbi(String),
    #[error("unknown evidence artifact: {0}")]
    UnknownArtifact(String),
    #[error("failed to read evidence file: {0}")]
    Io(std::io::Error),
    #[error("evidence file {path} has size {actual}, expected {expected}")]
    SizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("evidence file {path} has SHA-256 {actual}, expected {expected}")]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}
