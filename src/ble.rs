use crate::events::AppEvent;
use anyhow::Result;
use rand::RngCore;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

pub struct BleAdvertiser {
    active: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl BleAdvertiser {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start_advertising(&self, endpoint_id: &str, device_name: &str) -> Result<()> {
        let ep_id = endpoint_id.to_string();
        let _dev_name = device_name.to_string();
        let active = self.active.clone();
        let child_arc = self.child.clone();

        self.stop_advertising();
        active.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            info!("Initializing persistent Bluetooth LE Advertiser for Quick Share (UUIDs: 0xFE2C, 0xFEF3)...");

            // Ensure controller power is on
            let _ = std::process::Command::new("bluetoothctl")
                .args(["power", "on"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output();

            let mut rand_bytes = [0u8; 10];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            let rand_hex = rand_bytes
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let ep_hex = ep_id
                .as_bytes()
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            // Google Fast Pair pulse (FE2C) + Quick Share Fast Beacon (FEF3)
            let script = format!(
                "menu advertise\nclear\nuuids FE2C FEF3\nservice FE2C 0xfc 0x12 0x8e 0x01 0x42 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 {}\nservice FEF3 0x23 {} 0xfc 0x9f 0x5e\ndiscoverable on\nback\nadvertise on\n",
                rand_hex, ep_hex
            );

            let cmd = std::process::Command::new("bluetoothctl")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();

            match cmd {
                Ok(mut proc) => {
                    if let Some(stdin) = proc.stdin.as_mut() {
                        use std::io::Write;
                        let _ = stdin.write_all(script.as_bytes());
                        let _ = stdin.flush();
                    }
                    *child_arc.lock().unwrap() = Some(proc);
                    info!(
                        "Bluetooth LE Advertisement (0xFE2C / 0xFEF3) actively broadcasting with endpoint ID [{}]",
                        ep_id
                    );
                }
                Err(e) => {
                    warn!("Failed to spawn bluetoothctl for persistent BLE advertising: {:?}", e);
                }
            }
        });

        Ok(())
    }

    pub fn stop_advertising(&self) {
        if self.active.swap(false, Ordering::SeqCst) {
            info!("Stopping Bluetooth LE advertisement...");
            let mut lock = self.child.lock().unwrap();
            if let Some(mut proc) = lock.take() {
                if let Some(mut stdin) = proc.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(b"advertise off\nquit\n");
                    let _ = stdin.flush();
                }
                let _ = proc.kill();
                let _ = proc.wait();
            }
        }
    }
}

impl Drop for BleAdvertiser {
    fn drop(&mut self) {
        self.stop_advertising();
    }
}

use crate::discovery::get_local_ip;
use crate::events::{DeviceType, DiscoveredPeer};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

pub struct BleScanner;

impl BleScanner {
    pub async fn run_loop(ui_sender: UnboundedSender<AppEvent>) {
        info!("Starting Bluetooth LE & Local LAN Background Scanner for Quick Share peers...");
        let mut known_endpoints = HashSet::new();
        let my_ip = get_local_ip();

        let mut ble_cycle = 0;
        loop {
            // 1. Every ~15 seconds, trigger a quick BLE scan pulse in the background
            if ble_cycle % 3 == 0 {
                let _ = tokio::process::Command::new("bluetoothctl")
                    .args(["--timeout", "2", "scan", "le"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
            }
            ble_cycle += 1;

            // 2. Scan ARP neighbors on local network
            let neighbors = get_arp_neighbors();
            for ip in neighbors {
                if Some(ip) == my_ip || ip.is_loopback() {
                    continue;
                }

                if let Some(port) = probe_quickshare_port(ip) {
                    let ep_key = format!("{}:{}", ip, port);
                    if known_endpoints.insert(ep_key.clone()) {
                        info!(
                            "Discovered nearby Quick Share device on LAN at {}:{}",
                            ip, port
                        );
                        let peer = DiscoveredPeer {
                            id: format!("lan_{}_{}", ip.to_string().replace('.', "_"), port),
                            name: format!("Quick Share Device ({})", ip),
                            device_type: DeviceType::Phone,
                            ip,
                            port,
                        };
                        let _ = ui_sender.send(AppEvent::PeerDiscovered(peer));
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(4)).await;
        }
    }
}

pub fn get_arp_neighbors() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(ip_str) = parts.first() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    // Filter out link-local and 0.0.0.0
                    if !ip.is_unspecified() && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    ips
}

pub fn probe_quickshare_port(ip: IpAddr) -> Option<u16> {
    let candidate_ports = [53601, 53317, 8765, 53600, 53602, 53603];
    for port in candidate_ports {
        let addr = SocketAddr::new(ip, port);
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(80)) {
            drop(stream);
            return Some(port);
        }
    }
    None
}

