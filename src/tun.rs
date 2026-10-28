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
    #[error("TUN is not supported on this platform")]
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
    #[error("failed to execute network command: {0}")]
    ConfigureCommand(std::io::Error),
    #[error("network command failed with status {status}: {arguments}")]
    ConfigureStatus { status: String, arguments: String },
}

pub fn macos_interface_commands(
    interface_name: &str,
    address: Ipv4Addr,
    overlay_network: &str,
) -> Result<Vec<Vec<String>>, TunError> {
    validate_macos_interface_name(interface_name)?;
    let prefix = validate_overlay(address, overlay_network)?;
    let mask = prefix_to_ipv4_mask(prefix);
    Ok(vec![vec![
        interface_name.to_owned(),
        "inet".to_owned(),
        address.to_string(),
        address.to_string(),
        "netmask".to_owned(),
        mask.to_string(),
        "up".to_owned(),
    ]])
}

pub fn macos_member_route_commands(
    interface_name: &str,
    local_address: Ipv4Addr,
    overlay_network: &str,
    previous_members: &[Ipv4Addr],
    current_members: &[Ipv4Addr],
) -> Result<Vec<Vec<String>>, TunError> {
    validate_macos_interface_name(interface_name)?;
    let prefix = validate_overlay(local_address, overlay_network)?;
    let (network, _) = parse_overlay_network(overlay_network)?;
    let mask = prefix_to_mask(prefix);
    let network_bits = u32::from(network);

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
            "-n".to_owned(),
            "add".to_owned(),
            "-host".to_owned(),
            address.to_string(),
            "-interface".to_owned(),
            interface_name.to_owned(),
        ]);
    }
    for address in previous.difference(&current) {
        commands.push(vec![
            "-n".to_owned(),
            "delete".to_owned(),
            "-host".to_owned(),
            address.to_string(),
        ]);
    }
    Ok(commands)
}

pub fn encode_macos_utun_packet(packet: &[u8]) -> Result<Vec<u8>, TunError> {
    if packet.first().map(|byte| byte >> 4) != Some(4) {
        return Err(TunError::Operation(
            "utun accepts only IPv4 packets for this client".to_owned(),
        ));
    }
    let mut framed = Vec::with_capacity(4 + packet.len());
    framed.extend_from_slice(&2_u32.to_be_bytes());
    framed.extend_from_slice(packet);
    Ok(framed)
}

pub fn decode_macos_utun_packet(frame: &[u8], output: &mut [u8]) -> Result<usize, TunError> {
    if frame.len() < 5 {
        return Err(TunError::Operation("utun frame is too short".to_owned()));
    }
    if frame[..4] != 2_u32.to_be_bytes() {
        return Err(TunError::Operation("utun frame is not IPv4".to_owned()));
    }
    let packet = &frame[4..];
    if packet.len() > output.len() {
        return Err(TunError::Operation(format!(
            "utun packet of {} bytes exceeds buffer of {} bytes",
            packet.len(),
            output.len()
        )));
    }
    output[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}

fn validate_macos_interface_name(interface_name: &str) -> Result<(), TunError> {
    macos_utun_unit(interface_name)?;
    Ok(())
}

pub fn macos_utun_unit(interface_name: &str) -> Result<u32, TunError> {
    let Some(unit) = interface_name.strip_prefix("utun") else {
        return Err(TunError::InvalidInterfaceName(interface_name.to_owned()));
    };
    if unit.is_empty() || !unit.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TunError::InvalidInterfaceName(interface_name.to_owned()));
    }
    let parsed = unit
        .parse::<u32>()
        .map_err(|_| TunError::InvalidInterfaceName(interface_name.to_owned()))?;
    parsed
        .checked_add(1)
        .ok_or_else(|| TunError::InvalidInterfaceName(interface_name.to_owned()))
}

fn parse_overlay_network(overlay_network: &str) -> Result<(Ipv4Addr, u8), TunError> {
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
    if u32::from(network) & prefix_to_mask(prefix) != u32::from(network) {
        return Err(TunError::InvalidOverlayNetwork(overlay_network.to_owned()));
    }
    Ok((network, prefix))
}

fn validate_overlay(address: Ipv4Addr, overlay_network: &str) -> Result<u8, TunError> {
    let (network, prefix) = parse_overlay_network(overlay_network)?;
    if u32::from(address) & prefix_to_mask(prefix) != u32::from(network) {
        return Err(TunError::AddressOutsideNetwork {
            address,
            network: overlay_network.to_owned(),
        });
    }
    Ok(prefix)
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn prefix_to_ipv4_mask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(prefix_to_mask(prefix))
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

#[cfg(target_os = "macos")]
pub fn configure_macos_interface(
    interface_name: &str,
    address: Ipv4Addr,
    overlay_network: &str,
) -> Result<(), TunError> {
    for arguments in macos_interface_commands(interface_name, address, overlay_network)? {
        let status = std::process::Command::new("/sbin/ifconfig")
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

#[cfg(target_os = "macos")]
pub fn configure_macos_member_routes(
    interface_name: &str,
    local_address: Ipv4Addr,
    overlay_network: &str,
    previous_members: &[Ipv4Addr],
    current_members: &[Ipv4Addr],
) -> Result<(), TunError> {
    for arguments in macos_member_route_commands(
        interface_name,
        local_address,
        overlay_network,
        previous_members,
        current_members,
    )? {
        let status = std::process::Command::new("/sbin/route")
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

#[cfg(not(target_os = "macos"))]
pub fn configure_macos_interface(
    _interface_name: &str,
    _address: Ipv4Addr,
    _overlay_network: &str,
) -> Result<(), TunError> {
    Err(TunError::UnsupportedPlatform)
}

#[cfg(not(target_os = "macos"))]
pub fn configure_macos_member_routes(
    _interface_name: &str,
    _local_address: Ipv4Addr,
    _overlay_network: &str,
    _previous_members: &[Ipv4Addr],
    _current_members: &[Ipv4Addr],
) -> Result<(), TunError> {
    Err(TunError::UnsupportedPlatform)
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

pub struct MacOsTunBackend {
    interface_name: String,
}

impl MacOsTunBackend {
    pub fn new(interface_name: impl Into<String>) -> Result<Self, TunError> {
        let interface_name = interface_name.into();
        macos_utun_unit(&interface_name)?;
        Ok(Self { interface_name })
    }
}

#[cfg(target_os = "macos")]
impl TunBackend for MacOsTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        use std::fs::File;
        use std::os::fd::{AsRawFd, FromRawFd};

        let descriptor =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if descriptor < 0 {
            return Err(TunError::Open(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(descriptor) };

        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let control_name = b"com.apple.net.utun_control\0";
        for (destination, source) in info.ctl_name.iter_mut().zip(control_name.iter()) {
            *destination = *source as libc::c_char;
        }
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::CTLIOCGINFO, &mut info) } < 0 {
            return Err(TunError::Create {
                name: self.interface_name.clone(),
                source: std::io::Error::last_os_error(),
            });
        }

        let address = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: macos_utun_unit(&self.interface_name)?,
            sc_reserved: [0; 5],
        };
        let result = unsafe {
            libc::connect(
                file.as_raw_fd(),
                &address as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
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

        Ok(Box::new(MacOsTunDevice {
            file: Some(file),
            read_buffer: Vec::new(),
        }))
    }
}

#[cfg(not(target_os = "macos"))]
impl TunBackend for MacOsTunBackend {
    fn create(&mut self, _address: IpAddr) -> Result<Box<dyn TunDevice>, TunError> {
        let _ = self.interface_name.as_str();
        Err(TunError::UnsupportedPlatform)
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

#[cfg(target_os = "macos")]
struct MacOsTunDevice {
    file: Option<std::fs::File>,
    read_buffer: Vec<u8>,
}

#[cfg(target_os = "macos")]
impl TunDevice for MacOsTunDevice {
    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, TunError> {
        use std::io::Read;

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| TunError::Operation("utun device is closed".to_owned()))?;
        self.read_buffer.resize(buffer.len().saturating_add(4), 0);
        match file.read(&mut self.read_buffer) {
            Ok(0) => Err(TunError::Operation(
                "utun returned an unexpected end of file".to_owned(),
            )),
            Ok(length) => decode_macos_utun_packet(&self.read_buffer[..length], buffer).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(TunError::Operation(format!("utun read failed: {error}"))),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError> {
        use std::io::Write;

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| TunError::Operation("utun device is closed".to_owned()))?;
        let framed = encode_macos_utun_packet(packet)?;
        match file.write(&framed) {
            Ok(length) if length == framed.len() => Ok(()),
            Ok(length) => Err(TunError::Operation(format!(
                "utun short write: wrote {length} of {} bytes",
                framed.len()
            ))),
            Err(error) => Err(TunError::Operation(format!("utun write failed: {error}"))),
        }
    }

    fn try_clone_device(&self) -> Result<Box<dyn TunDevice>, TunError> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| TunError::Operation("utun device is closed".to_owned()))?
            .try_clone()
            .map_err(|error| TunError::Operation(format!("utun clone failed: {error}")))?;
        Ok(Box::new(Self {
            file: Some(file),
            read_buffer: Vec::new(),
        }))
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
