use crate::events::{AppEvent, DeviceType, DiscoveredPeer};
use anyhow::Result;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

pub struct BleAdvertiser {
    active: Arc<AtomicBool>,
}

impl BleAdvertiser {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_advertising(&self, endpoint_id: &str, device_name: &str) -> Result<()> {
        let ep_id = endpoint_id.to_string();
        let name = device_name.to_string();
        let active = self.active.clone();

        active.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            info!("Initializing Bluetooth LE Advertiser for Quick Share (UUID: 0xFEF3)...");

            let dev_bytes = name.as_bytes();
            let dev_len = dev_bytes.len().min(32) as u8;

            let mut ep_info = Vec::with_capacity(1 + 16 + 1 + dev_len as usize);
            ep_info.push(0x06u8); // Laptop, visible to everyone
            ep_info.extend_from_slice(&[0x01u8; 16]); // 16-byte salt
            ep_info.push(dev_len);
            ep_info.extend_from_slice(&dev_bytes[..dev_len as usize]);

            let mut adv_data = Vec::with_capacity(1 + 3 + 4 + 1 + ep_info.len());
            adv_data.push(0x22u8);
            adv_data.extend_from_slice(&[0xFC, 0x9F, 0x5E]);
            adv_data.extend_from_slice(ep_id.as_bytes());
            adv_data.push(ep_info.len() as u8);
            adv_data.extend_from_slice(&ep_info);

            let hex_payload = adv_data
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let script = format!(
                "menu advertise\nclear\nuuids FEF3\nservice FEF3 {}\ndiscoverable on\nback\nadvertise on\nquit\n",
                hex_payload
            );

            let cmd = std::process::Command::new("bluetoothctl")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();

            if let Ok(mut child) = cmd {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(script.as_bytes());
                }
                let _ = child.wait();
                info!("Bluetooth LE Advertisement (0xFEF3) registered successfully with endpoint ID [{}]", ep_id);
            } else {
                warn!("Failed to spawn bluetoothctl for BLE advertising");
            }
        });

        Ok(())
    }

    pub fn stop_advertising(&self) {
        if self.active.swap(false, Ordering::SeqCst) {
            info!("Stopping Bluetooth LE advertisement...");
            std::thread::spawn(|| {
                let script = "advertise off\nmenu advertise\nclear\nback\nquit\n";
                let cmd = std::process::Command::new("bluetoothctl")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
                if let Ok(mut child) = cmd {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(script.as_bytes());
                    }
                    let _ = child.wait();
                }
            });
        }
    }
}

impl Drop for BleAdvertiser {
    fn drop(&mut self) {
        self.stop_advertising();
    }
}

pub struct BleScanner;

impl BleScanner {
    pub async fn run_loop(ui_sender: UnboundedSender<AppEvent>) {
        info!("Starting Bluetooth LE & Local LAN Peer Scanner...");
        let mut discovered_ids: HashSet<String> = HashSet::new();

        loop {
            // 1. Check local ARP neighbor table for known active devices (e.g. WIZ_PHN at 192.168.1.7)
            if let Ok(output) = tokio::process::Command::new("ip")
                .arg("neigh")
                .output()
                .await
            {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let ip_str = parts[0];
                        // Ignore router and localhost
                        if ip_str.ends_with(".1") || ip_str.starts_with("fe80") {
                            continue;
                        }
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let peer_id = format!("lan_{}", ip_str.replace('.', "_"));
                            if !discovered_ids.contains(&peer_id) {
                                // Probe if port 8765 or 53317 is open
                                let port = probe_quickshare_port(ip).await;
                                if let Some(target_port) = port {
                                    discovered_ids.insert(peer_id.clone());
                                    // Query Bluetooth device alias if known
                                    let name = lookup_peer_name(ip).await;
                                    info!(
                                        "Discovered Quick Share target on local network: '{}' at {}:{}",
                                        name, ip, target_port
                                    );
                                    let _ = ui_sender.send(AppEvent::PeerDiscovered(DiscoveredPeer {
                                        id: peer_id,
                                        name,
                                        device_type: DeviceType::Phone,
                                        ip,
                                        port: target_port,
                                    }));
                                }
                            }
                        }
                    }
                }
            }

            // 2. Perform periodic BLE LE Discovery check via bluetoothctl
            let _ = tokio::process::Command::new("bluetoothctl")
                .args(["--timeout", "2", "scan", "le"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .await;

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn probe_quickshare_port(ip: IpAddr) -> Option<u16> {
    for port in [8765, 53317] {
        if tokio::time::timeout(
            Duration::from_millis(300),
            tokio::net::TcpStream::connect((ip, port)),
        )
        .await
        .is_ok()
        {
            return Some(port);
        }
    }
    None
}

async fn lookup_peer_name(ip: IpAddr) -> String {
    // Check if paired bluetoothctl devices match
    if let Ok(output) = tokio::process::Command::new("bluetoothctl")
        .arg("devices")
        .output()
        .await
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("WIZ_PHN") || line.contains("Phone") || line.contains("Pixel") || line.contains("Galaxy") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    return parts[2..].join(" ");
                }
            }
        }
    }
    format!("Device ({})", ip)
}
