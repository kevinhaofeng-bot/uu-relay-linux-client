use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use thiserror::Error;

pub trait TunDevice: Send {
    fn read_packet(&mut self, _buffer: &mut [u8]) -> Result<Option<usize>, TunError> {
        Err(TunError::Operation(
            "packet reads are not implemented by this TUN device".to_owned(),
        ))
    }

    fn write_packet(&mut self, _packet: &[u8]) -> Result<(), TunError> {
        Err(TunError::Operation(
            "packet writes are not implemented by this TUN device".to_owned(),
        ))
    }

    fn try_clone_device(&self) -> Result<Box<dyn TunDevice>, TunError> {
        Err(TunError::Operation(
            "TUN cloning is not implemented by this device".to_owned(),
        ))
    }

    fn close(&mut self) -> Result<(), TunError>;
}

pub trait TunBackend {
    fn create(&mut self, address: IpAddr) -> Result<Box<dyn TunDevice>, TunError>;
}

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN is supported only on Linux")]
    UnsupportedPlatform,
    #[error("invalid TUN interface name: {0}")]
    InvalidInterfaceName(String),
    #[error("invalid IPv4 overlay network: {0}")]
    InvalidOverlayNetwork(String),
    #[error("overlay address {address} is outside network {network}")]
    AddressOutsideNetwork { address: Ipv4Addr, network: String },
    #[error("room member {address} is outside network {network}")]
    MemberOutsideNetwork { address: Ipv4Addr, network: String },
    #[error("failed to open /dev/net/tun: {0}")]
    Open(std::io::Error),
    #[error("failed to create TUN interface {name}: {source}")]
    Create {
        name: String,
        source: std::io::Error,
    },
    #[error("TUN operation failed: {0}")]
    Operation(String),
    #[error("failed to execute ip command: {0}")]
    ConfigureCommand(std::io::Error),
    #[error("ip command failed with status {status}: {arguments}")]
    ConfigureStatus { status: String, arguments: String },
}

pub fn linux_interface_commands(
    interface_name: &str,
    address: Ipv4Addr,
    overlay_network: &str,
) -> Result<Vec<Vec<String>>, TunError> {
    LinuxTunBackend::new(interface_name)?;

    let (network_text, prefix_text) = overlay_network
        .split_once('/')
        .ok_or_else(|| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let network = network_text
        .parse::<Ipv4Addr>()
        .map_err(|_| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let prefix = prefix_text
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network_bits = u32::from(network);
    if network_bits & mask != network_bits {
        return Err(TunError::InvalidOverlayNetwork(overlay_network.to_owned()));
    }
    if u32::from(address) & mask != network_bits {
        return Err(TunError::AddressOutsideNetwork {
            address,
            network: overlay_network.to_owned(),
        });
    }

    Ok(vec![
        vec![
            "address".to_owned(),
            "replace".to_owned(),
            format!("{address}/{prefix}"),
            "dev".to_owned(),
            interface_name.to_owned(),
        ],
        vec![
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            interface_name.to_owned(),
            "up".to_owned(),
        ],
    ])
}

pub fn linux_member_route_commands(
    interface_name: &str,
    local_address: Ipv4Addr,
    overlay_network: &str,
    previous_members: &[Ipv4Addr],
    current_members: &[Ipv4Addr],
) -> Result<Vec<Vec<String>>, TunError> {
    LinuxTunBackend::new(interface_name)?;

    let (network_text, prefix_text) = overlay_network
        .split_once('/')
        .ok_or_else(|| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let network = network_text
        .parse::<Ipv4Addr>()
        .map_err(|_| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let prefix = prefix_text
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| TunError::InvalidOverlayNetwork(overlay_network.to_owned()))?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network_bits = u32::from(network);
    if network_bits & mask != network_bits {
        return Err(TunError::InvalidOverlayNetwork(overlay_network.to_owned()));
    }
    if u32::from(local_address) & mask != network_bits {
        return Err(TunError::AddressOutsideNetwork {
            address: local_address,
            network: overlay_network.to_owned(),
        });
    }

    let previous = previous_members.iter().copied().collect::<BTreeSet<_>>();
    let current = current_members.iter().copied().collect::<BTreeSet<_>>();
    for address in previous.union(&current) {
        if u32::from(*address) & mask != network_bits {
            return Err(TunError::MemberOutsideNetwork {
                address: *address,
                network: overlay_network.to_owned(),
            });
        }
    }

    let mut commands = Vec::new();
    for address in current.difference(&previous) {
        commands.push(vec![
            "route".to_owned(),
            "replace".to_owned(),
            format!("{address}/32"),
            "dev".to_owned(),
            interface_name.to_owned(),
            "src".to_owned(),
            local_address.to_string(),
        ]);
    }
    for address in previous.difference(&current) {
        commands.push(vec![
            "route".to_owned(),
            "del".to_owned(),
            format!("{address}/32"),
            "dev".to_owned(),
            interface_name.to_owned(),
        ]);
    }
    Ok(commands)
}

#[cfg(target_os = "linux")]
pub fn configure_linux_interface(
    interface_name: &str,
    address: Ipv4Addr,
    overlay_network: &str,
) -> Result<(), TunError> {
    for arguments in linux_interface_commands(interface_name, address, overlay_network)? {
        let status = std::process::Command::new("ip")
            .args(&arguments)
            .status()
            .map_err(TunError::ConfigureCommand)?;
        if !status.success() {
            return Err(TunError::ConfigureStatus {
                status: status.to_string(),
                arguments: arguments.join(" "),
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn configure_linux_member_routes(
    interface_name: &str,
    local_address: Ipv4Addr,
    overlay_network: &str,
    previous_members: &[Ipv4Addr],
    current_members: &[Ipv4Addr],
) -> Result<(), TunError> {
    for arguments in linux_member_route_commands(
        interface_name,
        local_address,
        overlay_network,
        previous_members,
        current_members,
    )? {
        let status = std::process::Command::new("ip")
            .args(&arguments)
            .status()
            .map_err(TunError::ConfigureCommand)?;
        if !status.success() {
            return Err(TunError::ConfigureStatus {
                status: status.to_string(),
                arguments: arguments.join(" "),
            });
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_linux_interface(
    _interface_name: &str,
    _address: Ipv4Addr,
    _overlay_network: &str,
) -> Result<(), TunError> {
    Err(TunError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn configure_linux_member_routes(
    _interface_name: &str,
    _local_address: Ipv4Addr,
    _overlay_network: &str,
    _previous_members: &[Ipv4Addr],
    _current_members: &[Ipv4Addr],
) -> Result<(), TunError> {
    Err(TunError::UnsupportedPlatform)
}

pub struct LinuxTunBackend {
    interface_name: String,
}

impl LinuxTunBackend {
    pub fn new(interface_name: impl Into<String>) -> Result<Self, TunError> {
        let interface_name = interface_name.into();
        if interface_name.is_empty()
            || interface_name.len() >= interface_name_limit()
            || interface_name.as_bytes().contains(&0)
        {
            return Err(TunError::InvalidInterfaceName(interface_name));
        }
        Ok(Self { interface_name })
    }
}

#[cfg(target_os = "linux")]
impl TunBackend for LinuxTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(TunError::Open)?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (index, byte) in self.interface_name.bytes().enumerate() {
            request.ifr_name[index] = byte as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &request) };
        if result < 0 {
            return Err(TunError::Create {
                name: self.interface_name.clone(),
                source: std::io::Error::last_os_error(),
            });
        }
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(TunError::Operation(format!(
                "failed to set {} nonblocking: {}",
                self.interface_name,
                std::io::Error::last_os_error()
            )));
        }
        Ok(Box::new(LinuxTunDevice { file: Some(file) }))
    }
}

#[cfg(not(target_os = "linux"))]
impl TunBackend for LinuxTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        let _ = self.interface_name.as_str();
        Err(TunError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
struct LinuxTunDevice {
    file: Option<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl TunDevice for LinuxTunDevice {
    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, TunError> {
        use std::io::Read;

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| TunError::Operation("TUN device is closed".to_owned()))?;
        match file.read(buffer) {
            Ok(0) => Err(TunError::Operation(
                "TUN returned an unexpected end of file".to_owned(),
            )),
            Ok(length) => Ok(Some(length)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(TunError::Operation(format!("TUN read failed: {error}"))),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        use std::io::Write;

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| TunError::Operation("TUN device is closed".to_owned()))?;
        match file.write(packet) {
            Ok(length) if length == packet.len() => Ok(()),
            Ok(length) => Err(TunError::Operation(format!(
                "TUN short write: wrote {length} of {} bytes",
                packet.len()
            ))),
            Err(error) => Err(TunError::Operation(format!("TUN write failed: {error}"))),
        }
    }

    fn try_clone_device(&self) -> Result<Box<dyn TunDevice>, TunError> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| TunError::Operation("TUN device is closed".to_owned()))?
            .try_clone()
            .map_err(|error| TunError::Operation(format!("TUN clone failed: {error}")))?;
        Ok(Box::new(Self { file: Some(file) }))
    }

    fn close(&mut self) -> Result<(), TunError> {
        self.file.take();
        Ok(())
    }
}

const fn interface_name_limit() -> usize {
    #[cfg(target_os = "linux")]
    {
        libc::IFNAMSIZ
    }
    #[cfg(not(target_os = "linux"))]
    {
        16
    }
}
