use std::net::IpAddr;
use tokio::sync::oneshot;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Phone,
    Tablet,
    Laptop,
    Unknown,
}

impl DeviceType {
    pub fn icon_name(&self) -> &'static str {
        match self {
            DeviceType::Phone => "phone-symbolic",
            DeviceType::Tablet => "tablet-symbolic",
            DeviceType::Laptop => "computer-symbolic",
            DeviceType::Unknown => "network-workgroup-symbolic",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            DeviceType::Phone => "Phone",
            DeviceType::Tablet => "Tablet",
            DeviceType::Laptop => "Laptop",
            DeviceType::Unknown => "Device",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug)]
pub enum AppEvent {
    PeerDiscovered(DiscoveredPeer),
    PeerLost(String),
    IncomingTransferRequest {
        session_id: u64,
        peer_name: String,
        files: Vec<(String, u64)>,
        total_size: u64,
        pin: String,
        accept_tx: oneshot::Sender<bool>,
    },
    TransferStarted {
        transfer_id: u64,
        filename: String,
        total: u64,
        is_send: bool,
    },
    TransferProgress {
        transfer_id: u64,
        filename: String,
        transferred: u64,
        total: u64,
        speed_mbps: f64,
        is_send: bool,
    },
    TransferCompleted {
        transfer_id: u64,
        filename: String,
        file_path: Option<std::path::PathBuf>,
        is_send: bool,
    },
    TransferFailed {
        transfer_id: u64,
        filename: String,
        error: String,
    },
    StatusNotification(String),
}
