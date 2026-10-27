use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::official_api::LoginCredentials;

const REDACTED: &str = "<redacted>";

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    room_id: String,
    client_id: String,
    overlay_address: IpAddr,
    #[serde(default)]
    session_id: Option<SecretString>,
    #[serde(default)]
    session_token: Option<SecretString>,
    #[serde(default)]
    mobile: Option<SecretString>,
    #[serde(default)]
    vlan_session: Option<SecretString>,
    #[serde(default)]
    room_password: Option<SecretString>,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(ConfigError::Io)?;
        ensure_private_permissions(&file, path)?;

        let mut input = String::new();
        file.read_to_string(&mut input).map_err(ConfigError::Io)?;
        Self::from_json(&input)
    }

    pub fn from_json(input: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(input).map_err(ConfigError::InvalidJson)?;
        config.validate()?;
        Ok(config)
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn overlay_address(&self) -> IpAddr {
        self.overlay_address
    }

    pub fn diagnostics(&self) -> ConfigDiagnostics<'_> {
        ConfigDiagnostics {
            valid: true,
            room_id: &self.room_id,
            client_id: &self.client_id,
            overlay_address: self.overlay_address,
            session_id: self.session_id.as_ref(),
            session_token: self.session_token.as_ref(),
            mobile: self.mobile.as_ref(),
            vlan_session: self.vlan_session.as_ref(),
            room_password: self.room_password.as_ref(),
        }
    }

    pub fn official_login_credentials(&self) -> Result<LoginCredentials, ConfigError> {
        let session_id = self
            .session_id
            .as_ref()
            .ok_or(ConfigError::MissingSessionId)?;
        let session_token = self
            .session_token
            .as_ref()
            .ok_or(ConfigError::MissingSessionToken)?;
        LoginCredentials::new(
            session_id.expose().to_owned(),
            session_token.expose().to_owned(),
            self.mobile
                .as_ref()
                .map(SecretString::expose)
                .unwrap_or_default()
                .to_owned(),
        )
        .map_err(|_| ConfigError::InvalidLoginCredentials)
    }

    pub fn room_password_for_api(&self) -> &str {
        self.room_password
            .as_ref()
            .map(SecretString::expose)
            .unwrap_or_default()
    }

    pub fn vlan_session_for_api(&self) -> Option<&str> {
        self.vlan_session.as_ref().map(SecretString::expose)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !is_valid_room_id(&self.room_id) {
            return Err(ConfigError::InvalidRoomId(self.room_id.clone()));
        }
        if self.client_id.trim().is_empty() {
            return Err(ConfigError::InvalidClientId);
        }
        if self.overlay_address.is_unspecified() {
            return Err(ConfigError::InvalidOverlayAddress(
                self.overlay_address.to_string(),
            ));
        }
        if self
            .session_token
            .as_ref()
            .is_some_and(|value| value.expose().is_empty())
            || self
                .vlan_session
                .as_ref()
                .is_some_and(|value| value.expose().is_empty())
            || (self.session_token.is_none() && self.vlan_session.is_none())
        {
            return Err(ConfigError::MissingSessionToken);
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ConfigDiagnostics<'a> {
    valid: bool,
    room_id: &'a str,
    client_id: &'a str,
    overlay_address: IpAddr,
    session_id: Option<&'a SecretString>,
    session_token: Option<&'a SecretString>,
    mobile: Option<&'a SecretString>,
    vlan_session: Option<&'a SecretString>,
    room_password: Option<&'a SecretString>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretString(String);

impl SecretString {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(std::io::Error),
    #[error("configuration is not valid JSON: {0}")]
    InvalidJson(serde_json::Error),
    #[error("invalid UU room id: {0}")]
    InvalidRoomId(String),
    #[error("client_id must not be empty")]
    InvalidClientId,
    #[error("invalid overlay address: {0}")]
    InvalidOverlayAddress(String),
    #[error("session_token must not be empty")]
    MissingSessionToken,
    #[error("session_id is required for UU API login")]
    MissingSessionId,
    #[error("UU API login credentials are invalid")]
    InvalidLoginCredentials,
    #[error(
        "secret configuration {path} has insecure mode {mode:o}; expected no group/world access"
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },
}

fn is_valid_room_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && bytes[..2].iter().all(u8::is_ascii_uppercase)
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

#[cfg(unix)]
fn ensure_private_permissions(file: &File, path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file
        .metadata()
        .map_err(ConfigError::Io)?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(_file: &File, _path: &Path) -> Result<(), ConfigError> {
    Ok(())
}
