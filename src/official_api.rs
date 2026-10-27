use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::cookie::Jar;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::bootstrap::{BootstrapError, OfficialRoomJoin};

const OFFICIAL_API_BASE: &str = "https://service.uu.163.com/vlan/api/";
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const REDACTED: &str = "<redacted>";
static INSTALL_TLS_PROVIDER: Once = Once::new();

pub struct LoginCredentials {
    session_id: String,
    token: String,
    mobile: String,
}

impl LoginCredentials {
    pub fn new(
        session_id: impl Into<String>,
        token: impl Into<String>,
        mobile: impl Into<String>,
    ) -> Result<Self, OfficialApiError> {
        let credentials = Self {
            session_id: session_id.into(),
            token: token.into(),
            mobile: mobile.into(),
        };
        if credentials.session_id.is_empty() {
            return Err(OfficialApiError::MissingCredential("session_id"));
        }
        if credentials.token.is_empty() {
            return Err(OfficialApiError::MissingCredential("token"));
        }
        Ok(credentials)
    }
}

impl fmt::Debug for LoginCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginCredentials")
            .field("session_id", &REDACTED)
            .field("token", &REDACTED)
            .field("mobile", &REDACTED)
            .finish()
    }
}

impl Drop for LoginCredentials {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.token.zeroize();
        self.mobile.zeroize();
    }
}

pub struct OfficialApiClient {
    client: Client,
    base_url: Url,
}

impl OfficialApiClient {
    pub fn new() -> Result<Self, OfficialApiError> {
        Self::from_base_url(OFFICIAL_API_BASE)
    }

    pub fn new_with_vlan_session(vlan_session: &str) -> Result<Self, OfficialApiError> {
        let parsed = Url::parse(OFFICIAL_API_BASE).map_err(|_| OfficialApiError::InvalidBaseUrl)?;
        Self::from_parsed_base_url_with_vlan_session(parsed, vlan_session)
    }

    #[doc(hidden)]
    pub fn new_for_loopback_test(base_url: &str) -> Result<Self, OfficialApiError> {
        let parsed = Url::parse(base_url).map_err(|_| OfficialApiError::InvalidBaseUrl)?;
        let is_loopback = parsed
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if parsed.scheme() != "http" || !is_loopback {
            return Err(OfficialApiError::UnsafeTestEndpoint);
        }
        Self::from_parsed_base_url(parsed)
    }

    #[doc(hidden)]
    pub fn new_for_loopback_test_with_vlan_session(
        base_url: &str,
        vlan_session: &str,
    ) -> Result<Self, OfficialApiError> {
        let parsed = Url::parse(base_url).map_err(|_| OfficialApiError::InvalidBaseUrl)?;
        let is_loopback = parsed
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if parsed.scheme() != "http" || !is_loopback {
            return Err(OfficialApiError::UnsafeTestEndpoint);
        }
        Self::from_parsed_base_url_with_vlan_session(parsed, vlan_session)
    }

    pub fn login(&self, credentials: &LoginCredentials) -> Result<(), OfficialApiError> {
        let payload = LoginPayload {
            session_id: &credentials.session_id,
            token: &credentials.token,
            mobile: &credentials.mobile,
        };
        let body = self.send(
            self.client
                .post(self.endpoint("login/win/")?)
                .json(&payload),
        )?;
        let envelope: ApiEnvelope<serde_json::Value> =
            serde_json::from_slice(&body).map_err(|_| OfficialApiError::InvalidJson)?;
        ensure_success(envelope.code)
    }

    pub fn acceleration_servers(&self) -> Result<Vec<AccelerationServer>, OfficialApiError> {
        let body = self.send(self.client.get(self.endpoint("accs")?))?;
        let envelope: ApiEnvelope<Vec<AccelerationServer>> =
            serde_json::from_slice(&body).map_err(|_| OfficialApiError::InvalidJson)?;
        ensure_success(envelope.code)?;
        let servers = envelope.data.ok_or(OfficialApiError::MissingData)?;
        if servers.iter().any(|server| !server.server_id.is_valid()) {
            return Err(OfficialApiError::InvalidServerId);
        }
        Ok(servers)
    }

    pub fn join_room(
        &self,
        room_id: &str,
        room_password: &str,
        server_id: Option<&ServerId>,
    ) -> Result<OfficialRoomJoin, OfficialApiError> {
        if room_id.is_empty() {
            return Err(OfficialApiError::InvalidRoomId);
        }
        let payload = RoomJoinPayload {
            room_id,
            room_password,
            server_id,
        };
        let body = self.send(self.client.post(self.endpoint("room/join")?).json(&payload))?;
        let joined = OfficialRoomJoin::parse_http_response(&body, room_id)
            .map_err(OfficialApiError::Bootstrap)?;
        if joined.self_is_online() {
            return Ok(joined);
        }
        self.set_online()?;
        self.room_info(room_id)
    }

    pub fn room_info(&self, expected_room_id: &str) -> Result<OfficialRoomJoin, OfficialApiError> {
        let body = self.send(self.client.get(self.endpoint("room/info")?))?;
        OfficialRoomJoin::parse_http_response(&body, expected_room_id)
            .map_err(OfficialApiError::Bootstrap)
    }

    pub fn resume_room(
        &self,
        expected_room_id: &str,
    ) -> Result<OfficialRoomJoin, OfficialApiError> {
        let joined = self.room_info(expected_room_id)?;
        if joined.self_is_online() {
            return Ok(joined);
        }
        self.set_online()?;
        self.room_info(expected_room_id)
    }

    pub fn set_online(&self) -> Result<(), OfficialApiError> {
        self.post_without_body("room/online")
    }

    pub fn set_offline(&self) -> Result<(), OfficialApiError> {
        self.post_without_body("room/offline")
    }

    pub fn leave_room(&self) -> Result<(), OfficialApiError> {
        self.post_without_body("room/leave")
    }

    pub fn login_and_join_first_available(
        &self,
        credentials: &LoginCredentials,
        room_id: &str,
        room_password: &str,
    ) -> Result<OfficialRoomJoin, OfficialApiError> {
        self.login(credentials)?;
        let servers = self.acceleration_servers()?;
        let first = servers
            .first()
            .ok_or(OfficialApiError::NoAccelerationServers)?;
        self.join_room(room_id, room_password, Some(&first.server_id))
    }

    fn from_base_url(base_url: &str) -> Result<Self, OfficialApiError> {
        let parsed = Url::parse(base_url).map_err(|_| OfficialApiError::InvalidBaseUrl)?;
        Self::from_parsed_base_url(parsed)
    }

    fn from_parsed_base_url(base_url: Url) -> Result<Self, OfficialApiError> {
        if !base_url.path().ends_with('/') {
            return Err(OfficialApiError::InvalidBaseUrl);
        }
        INSTALL_TLS_PROVIDER.call_once(|| {
            if rustls::crypto::CryptoProvider::get_default().is_none() {
                let _ = rustls::crypto::ring::default_provider().install_default();
            }
        });
        let client = Client::builder()
            .cookie_store(true)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(OfficialApiError::Http)?;
        Ok(Self { client, base_url })
    }

    fn from_parsed_base_url_with_vlan_session(
        base_url: Url,
        vlan_session: &str,
    ) -> Result<Self, OfficialApiError> {
        if vlan_session.is_empty() {
            return Err(OfficialApiError::MissingCredential("vlan_session"));
        }
        if !base_url.path().ends_with('/') {
            return Err(OfficialApiError::InvalidBaseUrl);
        }
        INSTALL_TLS_PROVIDER.call_once(|| {
            if rustls::crypto::CryptoProvider::get_default().is_none() {
                let _ = rustls::crypto::ring::default_provider().install_default();
            }
        });
        let jar = Arc::new(Jar::default());
        let cookie = Zeroizing::new(format!("vlan_session={vlan_session}; Path=/; HttpOnly"));
        jar.add_cookie_str(&cookie, &base_url);
        let client = Client::builder()
            .cookie_provider(jar)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(OfficialApiError::Http)?;
        Ok(Self { client, base_url })
    }

    fn endpoint(&self, path: &str) -> Result<Url, OfficialApiError> {
        self.base_url
            .join(path)
            .map_err(|_| OfficialApiError::InvalidBaseUrl)
    }

    fn send(&self, request: RequestBuilder) -> Result<Zeroizing<Vec<u8>>, OfficialApiError> {
        let response = request
            .send()
            .map_err(OfficialApiError::Http)?
            .error_for_status()
            .map_err(OfficialApiError::Http)?;
        read_bounded_response(response)
    }

    fn post_without_body(&self, path: &str) -> Result<(), OfficialApiError> {
        let body = self.send(self.client.post(self.endpoint(path)?))?;
        let envelope: ApiEnvelope<serde_json::Value> =
            serde_json::from_slice(&body).map_err(|_| OfficialApiError::InvalidJson)?;
        ensure_success(envelope.code)
    }
}

#[derive(Debug, Deserialize)]
pub struct AccelerationServer {
    #[serde(alias = "id")]
    server_id: ServerId,
}

impl AccelerationServer {
    pub fn server_id(&self) -> &ServerId {
        &self.server_id
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerId {
    Number(i64),
    Text(String),
}

impl ServerId {
    fn is_valid(&self) -> bool {
        match self {
            Self::Number(value) => *value > 0,
            Self::Text(value) => !value.trim().is_empty(),
        }
    }
}

#[derive(Serialize)]
struct LoginPayload<'a> {
    session_id: &'a str,
    token: &'a str,
    mobile: &'a str,
}

#[derive(Serialize)]
struct RoomJoinPayload<'a> {
    room_id: &'a str,
    room_password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_id: Option<&'a ServerId>,
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    code: i64,
    data: Option<T>,
}

fn ensure_success(code: i64) -> Result<(), OfficialApiError> {
    if code <= 0 || code == 200 {
        Ok(())
    } else {
        Err(OfficialApiError::ApiRejected(code))
    }
}

fn read_bounded_response(mut response: Response) -> Result<Zeroizing<Vec<u8>>, OfficialApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(OfficialApiError::ResponseTooLarge);
    }
    let mut body = Zeroizing::new(Vec::new());
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(OfficialApiError::Io)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(OfficialApiError::ResponseTooLarge);
    }
    Ok(body)
}

#[derive(Debug, Error)]
pub enum OfficialApiError {
    #[error("UU login credential {0} must not be empty")]
    MissingCredential(&'static str),
    #[error("UU API base URL is invalid")]
    InvalidBaseUrl,
    #[error("test UU API endpoint must be an HTTP loopback address")]
    UnsafeTestEndpoint,
    #[error("UU API request failed: {0}")]
    Http(reqwest::Error),
    #[error("failed to read UU API response: {0}")]
    Io(std::io::Error),
    #[error("UU API response exceeded the safe size limit")]
    ResponseTooLarge,
    #[error("UU API response is not valid JSON")]
    InvalidJson,
    #[error("UU API rejected the request with code {0}")]
    ApiRejected(i64),
    #[error("UU API response has no data object")]
    MissingData,
    #[error("UU API returned an invalid acceleration server id")]
    InvalidServerId,
    #[error("UU API returned no acceleration servers")]
    NoAccelerationServers,
    #[error("UU room id must not be empty")]
    InvalidRoomId,
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
}
