use crate::events::{AppEvent, DeviceType, DiscoveredPeer};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, info, warn};

pub const QUICKSHARE_SERVICE_TYPE: &str = "_FC9F5ED42C8A._tcp.local.";

pub struct MdnsAdvertiser {
    daemon: ServiceDaemon,
    service_fullname: String,
    is_active: bool,
}

impl MdnsAdvertiser {
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| anyhow!("mDNS daemon init failed: {:?}", e))?;
        Ok(Self {
            daemon,
            service_fullname: String::new(),
            is_active: false,
        })
    }

    pub fn start_advertising(
        &mut self,
        device_name: &str,
        port: u16,
        ip_addr: Option<IpAddr>,
        custom_endpoint_id: Option<&str>,
    ) -> Result<String> {
        // Stop any current advertisement first
        self.stop_advertising();

        // 1. Generate or reuse 4-character endpoint ID
        let endpoint_id: String = match custom_endpoint_id {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => OsRng
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect(),
        };

        // 2. Build WifiLanServiceInfo byte buffer
        // In Google Nearby Connections / Quick Share specification:
        // Service Name (Instance Name) = Base64([version_and_pcp (1), endpoint_id (4), service_id_hash (3), 0x00, 0x00])
        let version_and_pcp = 0x23u8; // Version 1, PCP 3 (P2P_STAR V2)
        let service_id_hash = [0xFCu8, 0x9Fu8, 0x5Eu8]; // SHA-256("NearbySharing")[0..3]

        let mut instance_name_bytes = Vec::with_capacity(10);
        instance_name_bytes.push(version_and_pcp);
        instance_name_bytes.extend_from_slice(endpoint_id.as_bytes());
        instance_name_bytes.extend_from_slice(&service_id_hash);
        instance_name_bytes.extend_from_slice(&[0x00, 0x00]);
        let instance_name = URL_SAFE_NO_PAD.encode(&instance_name_bytes);

        // Header: (0 << 5) | (0 << 4) | (3 << 1) = 0x06 (V1, visible to everyone, Laptop device type)
        let header_byte = 0x06u8;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let dev_bytes = device_name.as_bytes();
        let dev_len = dev_bytes.len().min(19) as u8; // Clamped to 19 bytes for stock Android compatibility

        let mut endpoint_info = Vec::with_capacity(1 + 16 + 1 + dev_len as usize);
        endpoint_info.push(header_byte);
        endpoint_info.extend_from_slice(&salt);
        endpoint_info.push(dev_len);
        endpoint_info.extend_from_slice(&dev_bytes[..dev_len as usize]);

        let encoded_endpoint_info = URL_SAFE_NO_PAD.encode(&endpoint_info);

        // 3. TXT record: "n" contains base64 endpoint_info
        let mut properties = HashMap::new();
        properties.insert("n".to_string(), encoded_endpoint_info.clone());

        // Resolve host IP
        let host_name = format!("{}.local.", endpoint_id);
        let my_ip = match ip_addr {
            Some(ip) => ip,
            None => get_local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        };

        info!("Registering mDNS Service: [{}] on port {}", QUICKSHARE_SERVICE_TYPE, port);
        info!("  Endpoint ID:   {}", endpoint_id);
        info!("  Instance Name: {}", instance_name);
        info!("  Device Name:   {}", device_name);
        info!("  TXT (n):       {}", encoded_endpoint_info);
        info!("  IP Address:    {}", my_ip);

        let service = ServiceInfo::new(
            QUICKSHARE_SERVICE_TYPE,
            &instance_name,
            &host_name,
            my_ip,
            port,
            properties,
        )
        .map_err(|e| anyhow!("Failed to construct ServiceInfo: {:?}", e))?;

        self.service_fullname = service.get_fullname().to_string();
        self.daemon
            .register(service)
            .map_err(|e| anyhow!("Failed to register mDNS service: {:?}", e))?;

        self.is_active = true;
        info!("mDNS service successfully broadcasted!");
        Ok(endpoint_id)
    }

    pub fn stop_advertising(&mut self) {
        if self.is_active && !self.service_fullname.is_empty() {
            info!("Unregistering mDNS service: {}", self.service_fullname);
            let _ = self.daemon.unregister(&self.service_fullname);
            self.service_fullname.clear();
            self.is_active = false;
        }
    }

    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.is_active
    }
}

impl Drop for MdnsAdvertiser {
    fn drop(&mut self) {
        self.stop_advertising();
    }
}

pub struct MdnsBrowser {
    #[allow(dead_code)]
    daemon: ServiceDaemon,
    receiver: Receiver<ServiceEvent>,
}

impl MdnsBrowser {
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| anyhow!("mDNS daemon init failed: {:?}", e))?;
        let receiver = daemon
            .browse(QUICKSHARE_SERVICE_TYPE)
            .map_err(|e| anyhow!("Failed to browse mDNS: {:?}", e))?;
        Ok(Self { daemon, receiver })
    }

    pub async fn run_loop<F>(
        self,
        my_endpoint_id: Option<String>,
        my_port: Option<u16>,
        my_device_name: Option<String>,
        mut on_event: F,
    ) where
        F: FnMut(AppEvent) + Send + 'static,
    {
        info!("Started mDNS browsing for Quick Share peers ({})", QUICKSHARE_SERVICE_TYPE);
        let mut known_peers: HashMap<String, String> = HashMap::new(); // fullname -> id

        while let Ok(event) = self.receiver.recv_async().await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let fullname = info.get_fullname().to_string();
                    let port = info.get_port();
                    
                    // Pick primary IPv4 address or first IP
                    let addresses = info.get_addresses();
                    let ip = addresses
                        .iter()
                        .find(|addr| addr.is_ipv4())
                        .map(|addr| addr.to_ip_addr())
                        .or_else(|| addresses.iter().next().map(|addr| addr.to_ip_addr()));

                    let ip = match ip {
                        Some(ip) => ip,
                        None => {
                            debug!("Ignored peer with no IP addresses: {}", fullname);
                            continue;
                        }
                    };

                    // Extract instance name from fullname (first label before ._FC9F5ED42C8A)
                    let instance_name = fullname
                        .split('.')
                        .next()
                        .unwrap_or("");

                    let txt_n = info.get_property_val_str("n");

                    let (id, name, device_type) = parse_resolved_peer(instance_name, txt_n, &fullname);

                    // Ignore own advertisement:
                    // Check if service belongs to ourselves by ID, port, IP addresses, or device name
                    let any_addr_is_self = addresses.iter().any(|addr| is_self_ip(&addr.to_ip_addr()));

                    if is_self_peer_info(
                        &id,
                        &ip,
                        port,
                        &name,
                        my_endpoint_id.as_deref(),
                        my_port,
                        my_device_name.as_deref(),
                    ) || any_addr_is_self {
                        debug!(
                            "Ignored self mDNS service: [{}] '{}' at {}:{}",
                            id, name, ip, port
                        );
                        continue;
                    }

                    known_peers.insert(fullname.clone(), id.clone());

                    info!(
                        "Discovered Quick Share peer: '{}' ({:?}) at {}:{} [ID: {}]",
                        name, device_type, ip, port, id
                    );

                    on_event(AppEvent::PeerDiscovered(DiscoveredPeer {
                        id,
                        name,
                        device_type,
                        ip,
                        port,
                    }));
                }
                ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                    if let Some(id) = known_peers.remove(&fullname) {
                        info!("Peer removed: {} [{}]", fullname, id);
                        on_event(AppEvent::PeerLost(id));
                    }
                }
                other => {
                    debug!("mDNS browser event: {:?}", other);
                }
            }
        }
        warn!("mDNS browsing loop terminated");
    }
}

pub fn parse_resolved_peer(
    instance_name: &str,
    txt_n: Option<&str>,
    _fullname: &str,
) -> (String, String, DeviceType) {
    let mut ep_id = String::new();
    let mut dev_name = String::new();
    let mut dev_type = DeviceType::Unknown;

    // 1. Try to extract endpoint ID from instance name (8-byte base64 URL safe: [version, id[4], hash[3]])
    if let Ok(inst_bytes) = URL_SAFE_NO_PAD.decode(instance_name.as_bytes()) {
        if inst_bytes.len() >= 5 {
            ep_id = String::from_utf8_lossy(&inst_bytes[1..5]).to_string();
        }
    }

    // 2. Try to decode TXT record 'n'
    if let Some(n_val) = txt_n {
        if let Ok(n_bytes) = URL_SAFE_NO_PAD.decode(n_val.as_bytes()) {
            // Case A: Standard endpoint_info: [header(1), salt(16), name_len(1), name...]
            if n_bytes.len() >= 18 {
                let header = n_bytes[0];
                let raw_type = (header >> 1) & 0x07;
                dev_type = match raw_type {
                    1 => DeviceType::Phone,
                    2 => DeviceType::Tablet,
                    3 => DeviceType::Laptop,
                    _ => DeviceType::Unknown,
                };
                let name_len = n_bytes[17] as usize;
                if n_bytes.len() >= 18 + name_len {
                    dev_name = String::from_utf8_lossy(&n_bytes[18..18 + name_len]).to_string();
                }
            }

            // Case B: Combined format: [version(1), ep_id(4), hash(3), len(1), endpoint_info...]
            if dev_name.is_empty() && n_bytes.len() >= 9 {
                if ep_id.is_empty() {
                    ep_id = String::from_utf8_lossy(&n_bytes[1..5]).to_string();
                }
                let info_len = n_bytes[8] as usize;
                if n_bytes.len() >= 9 + info_len && info_len >= 18 {
                    let ep_info = &n_bytes[9..9 + info_len];
                    let header = ep_info[0];
                    let raw_type = (header >> 1) & 0x07;
                    dev_type = match raw_type {
                        1 => DeviceType::Phone,
                        2 => DeviceType::Tablet,
                        3 => DeviceType::Laptop,
                        _ => DeviceType::Unknown,
                    };
                    let name_len = ep_info[17] as usize;
                    if ep_info.len() >= 18 + name_len {
                        dev_name = String::from_utf8_lossy(&ep_info[18..18 + name_len]).to_string();
                    }
                }
            }
        }
    }

    if ep_id.is_empty() {
        ep_id = instance_name.chars().take(4).collect();
        if ep_id.is_empty() {
            ep_id = "PEER".to_string();
        }
    }

    if dev_name.is_empty() {
        dev_name = format!("Quick Share Device ({})", ep_id);
    }

    (ep_id, dev_name, dev_type)
}

pub fn get_local_ip() -> Option<IpAddr> {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                return Some(local_addr.ip());
            }
        }
    }
    None
}

pub fn get_all_local_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if !ips.contains(&iface.ip()) {
                ips.push(iface.ip());
            }
        }
    }
    if let Some(primary) = get_local_ip() {
        if !ips.contains(&primary) {
            ips.push(primary);
        }
    }
    ips
}

pub fn is_self_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let all = get_all_local_ips();
    all.contains(ip)
}

pub fn is_self_peer_info(
    peer_id: &str,
    peer_ip: &IpAddr,
    peer_port: u16,
    peer_name: &str,
    my_endpoint_id: Option<&str>,
    my_port: Option<u16>,
    my_device_name: Option<&str>,
) -> bool {
    // 1. Endpoint ID matches our own
    if let Some(my_id) = my_endpoint_id {
        if !my_id.is_empty() && peer_id == my_id {
            return true;
        }
    }

    // 2. IP belongs to our own machine
    if is_self_ip(peer_ip) {
        return true;
    }

    // 3. Port and name match our own service
    if let (Some(my_p), Some(my_n)) = (my_port, my_device_name) {
        if peer_port == my_p && peer_name == my_n {
            return true;
        }
    }

    false
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertiser_and_parsed_peer() {
        let endpoint_id = "ABCD".to_string();
        let version_and_pcp = 0x23u8;
        let service_id_hash = [0xFCu8, 0x9Fu8, 0x5Eu8];

        let mut instance_name_bytes = Vec::with_capacity(10);
        instance_name_bytes.push(version_and_pcp);
        instance_name_bytes.extend_from_slice(endpoint_id.as_bytes());
        instance_name_bytes.extend_from_slice(&service_id_hash);
        instance_name_bytes.extend_from_slice(&[0x00, 0x00]);
        let instance_name = URL_SAFE_NO_PAD.encode(&instance_name_bytes);

        let dev_name = "My Linux PC";
        let header_byte = 0x06u8;
        let salt = [1u8; 16];
        let dev_bytes = dev_name.as_bytes();
        let dev_len = dev_bytes.len().min(19) as u8;

        let mut endpoint_info = Vec::with_capacity(1 + 16 + 1 + dev_len as usize);
        endpoint_info.push(header_byte);
        endpoint_info.extend_from_slice(&salt);
        endpoint_info.push(dev_len);
        endpoint_info.extend_from_slice(&dev_bytes[..dev_len as usize]);
        let encoded_endpoint_info = URL_SAFE_NO_PAD.encode(&endpoint_info);

        let mut properties = HashMap::new();
        properties.insert("n".to_string(), encoded_endpoint_info.clone());

        let host_name = format!("{}.local.", endpoint_id);
        let service = ServiceInfo::new(
            QUICKSHARE_SERVICE_TYPE,
            &instance_name,
            &host_name,
            "192.168.1.50",
            53601,
            properties,
        ).unwrap();

        let fullname = service.get_fullname().to_string();
        println!("Service fullname: {}", fullname);

        let extracted_instance = fullname.split('.').next().unwrap_or("");
        println!("Extracted instance: {}", extracted_instance);

        let txt_n = service.get_property_val_str("n");
        let (id, name, dev_type) = parse_resolved_peer(extracted_instance, txt_n, &fullname);
        println!("Parsed: id={}, name={}, type={:?}", id, name, dev_type);

        assert_eq!(id, endpoint_id);
        assert_eq!(name, dev_name);
    }

    #[test]
    fn test_is_self_ip_filtering() {
        use std::str::FromStr;
        // Loopback and unspecified must be detected as self
        assert!(is_self_ip(&IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(is_self_ip(&IpAddr::from_str("127.0.0.2").unwrap()));
        assert!(is_self_ip(&IpAddr::from_str("::1").unwrap()));
        assert!(is_self_ip(&IpAddr::from_str("0.0.0.0").unwrap()));

        // Local interface IPs must be detected
        let local_ips = get_all_local_ips();
        for lip in local_ips {
            assert!(is_self_ip(&lip));
        }

        // Distinct external address should not be self
        let foreign_ip = IpAddr::from_str("203.0.113.199").unwrap();
        assert!(!is_self_ip(&foreign_ip));
    }

    #[test]
    fn test_is_self_peer_info_detection() {
        use std::str::FromStr;
        let self_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let other_ip = IpAddr::from_str("192.0.2.1").unwrap();

        // 1. Matches own endpoint ID
        assert!(is_self_peer_info("ABCD", &other_ip, 53601, "Pixel 8", Some("ABCD"), Some(53601), Some("My PC")));

        // 2. Matches self IP (e.g. loopback or host interface)
        assert!(is_self_peer_info("XYZ9", &self_ip, 53601, "Pixel 8", Some("ABCD"), Some(53601), Some("My PC")));

        // 3. Matches own device name and port
        assert!(is_self_peer_info("XYZ9", &other_ip, 53601, "My PC", Some("ABCD"), Some(53601), Some("My PC")));

        // 4. Truly distinct peer is NOT self
        assert!(!is_self_peer_info("XYZ9", &other_ip, 53601, "Pixel 8", Some("ABCD"), Some(53601), Some("My PC")));
    }
}


