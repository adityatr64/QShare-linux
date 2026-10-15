# QShare Linux

An interoperable, native Linux implementation of the Google Quick Share (formerly Nearby Share) protocol, providing bidirectional file transfer capabilities between Linux workstations, Android devices, and ChromeOS systems.

---

## Project Overview

QShare Linux is an open-source client and receiver daemon reverse-engineered from the Google Nearby Connections and Quick Share protocol specifications. It allows Linux desktop environments and headless servers to discover, authenticate, send, and receive files with Android and ChromeOS devices over local networks and Bluetooth Low Energy.

The project provides:
- A native desktop graphical user interface built with GTK4 and Libadwaita conforming to GNOME HIG standards.
- Full desktop application integration with .desktop entry, scalable icons, and launcher support for GNOME Dash, KDE KRunner, Rofi, and Wofi.
- Automated network and firewall configuration for seamless local device discovery.
- A headless daemon mode for servers and minimal installations.
- A command-line interface (CLI) for direct terminal-driven transmissions and network diagnostics.
- Native systemd user service integration for automated background reception.

Supported environments include modern Linux distributions running systemd and glibc or musl: Arch Linux, Fedora, Ubuntu, Debian, openSUSE, and Alpine Linux. Both Wayland and X11 display servers are supported.

---

## Architecture & How It Works

The Quick Share protocol stack operates in four distinct phases: Discovery, Pairing and Key Exchange, Secure Framing, and Payload Streaming.

### 1. Discovery Phase
- Bluetooth Low Energy (BLE): The daemon advertises a 16-bit Service UUID (`0xFEF3` for Nearby Sharing, and optionally `0xFE2C` for Fast Pair) using the standard Linux BlueZ D-Bus interface. The advertisement packet carries a 4-byte ephemeral endpoint ID, a 3-byte service ID hash (`0xFC9F5E`, computed as `SHA-256("NearbySharing")[0..3]`), and encoded device metadata. Nearby Android devices detect this beacon and immediately populate the Quick Share share sheet.
- Multicast DNS (mDNS / DNS-SD): Concurrently, the service registers an mDNS record under `_FC9F5ED42C8A._tcp.local.` on port 8765 (with dynamic fallback up to 8815). The instance name and `n` TXT attribute contain base64-encoded `WifiLanServiceInfo` structures containing the endpoint ID and sanitized device name.
- Peer Scanning: When sending from Linux, the application listens for mDNS PTR/SRV announcements and scans local subnet ARP tables (`/proc/net/arp` and Netlink neighbors) combined with targeted port probes (`53601`, `53317`, `8765`).

### 2. Pairing & Key Exchange (UKEY2)
Upon TCP connection establishment, both endpoints execute the UKEY2 (Universal Key Exchange 2) protocol:
- Cipher Negotiation: Negotiates Curve25519 (ECDH) key agreements with SHA-512 commitment verification.
- Secret Derivation: Ephemeral public keys and random nonces are exchanged across three handshake messages (`ClientInit`, `ServerInit`, `ClientFinished`).
- Authentication PIN: An authentic 4-digit mutual verification code is derived via HKDF extraction followed by modulo-9973 arithmetic on the derived authentication key. This identical PIN is shown on both sender and receiver displays to prevent man-in-the-middle attacks.

### 3. Secure Framing & Encryption
- Following the UKEY2 exchange, standard Protobuf communication is wrapped inside an authenticated `SecureMessage` envelope.
- Payload bodies are encrypted using AES-256-CBC with dynamic initialization vectors (IVs) derived per transmission.
- Message integrity is enforced through HMAC-SHA256 signatures evaluated over each frame prior to parsing.

### 4. Payload Streaming & Framing
- Transfers use a two-frame structure mandated by Android and Samsung One UI 7+. File data is fragmented into 64 KB or 512 KB chunks with `flags = 0`.
- Completion is signaled via a dedicated zero-byte terminator frame with `flags = 1` (`LAST_CHUNK`), followed by socket flushing, `PAYLOAD_RECEIVED_ACK` control packets, and clean `DisconnectionFrame` negotiations.

---

## AI Assistance & Ethics Disclaimer

This implementation was developed with the assistance of artificial intelligence systems during reverse-engineering exploration, packet analysis, and code generation. 

While the protocol logic, cryptographic primitives, and state machines have been tested against production Android 14/15 and ChromeOS devices, community review is actively requested. Developers and security researchers are encouraged to audit edge cases, protocol state machines, and cryptographic boundary implementations.

This project is intended strictly for interoperability purposes in accordance with reverse-engineering protections for software compatibility. No proprietary binaries or keys from Google LLC or Samsung Electronics are distributed within this repository.

---

## Acknowledgments & References

This implementation builds upon the foundational reverse-engineering research and documentation produced by the open-source community:
- [Google Nearby Connections Protocol](https://github.com/google/nearby): Google open-source Nearby specifications and core design references.
- [REA](https://github.com/morluto/rea): Reverse engineer anything with agents, from app behavior down to native binaries. 
- [Google UKEY2 Specification](https://github.com/google/ukey2): Universal Key Exchange 2 protocol specification and reference implementations.
- [rquickshare by Martichou](https://github.com/Martichou/rquickshare): Rust implementation of Quick Share client and receiver logic.
- [NearDrop by Grishka](https://github.com/grishka/NearDrop): macOS implementation of Google Nearby Share protocol.
- [Android Open Source Project (AOSP)](https://android.googlesource.com/): Reference implementations of Nearby Connections framing and transport protocols.
- [Wireshark Network Analyzer](https://www.wireshark.org/): Packet inspection and protocol dissectors used for analyzing live Android transmission traces.
- [GNOME Libadwaita](https://gitlab.gnome.org/GNOME/libadwaita): Modern HIG-compliant user interface components.
- [Avahi mDNS/DNS-SD](https://www.avahi.org/): Zero-configuration networking implementation for Linux.
- [BlueZ Linux Bluetooth Subsystem](http://www.bluez.org/): Bluetooth Low Energy advertising and D-Bus interfaces.
- [RFC 5869 (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function.

---

## Prerequisites & Dependencies

### System Packages

#### Debian / Ubuntu / Linux Mint
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libadwaita-1-dev libgtk-4-dev libgdk-pixbuf-2.0-dev libssl-dev protobuf-compiler avahi-daemon bluez
```

#### Arch Linux / Manjaro
```bash
sudo pacman -S --needed base-devel libadwaita gtk4 gdk-pixbuf2 openssl protobuf avahi bluez bluez-utils
```

#### Fedora / RHEL 9
```bash
sudo dnf install -y gcc gcc-c++ pkgconf-pkg-config libadwaita-devel gtk4-devel gdk-pixbuf2-devel openssl-devel protobuf-compiler avahi bluez
```

### System Services & Kernel Requirements
- Avahi Daemon: Ensure `avahi-daemon.service` is active for local DNS-SD operation:
  ```bash
  sudo systemctl enable --now avahi-daemon.service
  ```
- Bluetooth Service: Required for BLE beacon advertisement:
  ```bash
  sudo systemctl enable --now bluetooth.service
  ```
- Kernel Modules: Standard Linux Bluetooth (`bluetooth`, `hci_uart` or `btusb`) and network multicast support enabled by default in distribution kernels.

---

## Network & Firewall Setup

Quick Share requires local subnet connectivity between your Linux machine and mobile devices.

### Port & Socket Specifications

| Protocol | Port / Range | Type | Purpose | Direction |
|---|---|---|---|---|
| UDP | 5353 | Multicast (224.0.0.251) | mDNS / DNS-SD Device Discovery | Inbound / Outbound |
| TCP | 8765 - 8815 | Unicast (Stream) | Incoming Encrypted File Transfer Socket | Inbound |
| TCP | Ephemeral (53601, 53317, dynamic) | Unicast (Stream) | Outgoing Transfers to Android Targets | Outbound |
| BLE | Service UUID 0xFEF3 / 0xFE2C | D-Bus / HCI Broadcast | Fast Device Advertisement Beacon | Outbound Broadcast |

### Automated Firewall Configuration

You can configure the local firewall automatically using the included setup script or binary CLI command:

```bash
# Using the helper script (auto-detects UFW, firewalld, nftables)
sudo ./scripts/setup-firewall.sh

# Or using the application binary directly
QShare-linux --setup-firewall
```

### Manual Firewall Configuration Commands

#### UFW (Uncomplicated Firewall - Ubuntu, Debian)
```bash
# Allow mDNS discovery multicast
sudo ufw allow 5353/udp comment "Quick Share mDNS Discovery"

# Allow incoming file transfer TCP port range
sudo ufw allow 8765:8815/tcp comment "Quick Share File Transfers"

# Optional: Restrict incoming connections to your local subnet
# sudo ufw allow from 192.168.1.0/24 to any port 8765 proto tcp comment "Quick Share LAN Only"

sudo ufw reload
```

#### Firewalld (Fedora, RHEL, CentOS)
```bash
# Enable mDNS service
sudo firewall-cmd --permanent --add-service=mdns

# Open Quick Share transfer port range
sudo firewall-cmd --permanent --add-port=8765-8815/tcp

# Apply changes
sudo firewall-cmd --reload
```

#### iptables
```bash
# Allow mDNS UDP traffic
sudo iptables -A INPUT -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT

# Allow incoming TCP transfers on local subnet
sudo iptables -A INPUT -p tcp --dport 8765:8815 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
```

#### nftables
```bash
sudo nft add rule inet filter input udp dport 5353 ip daddr 224.0.0.251 accept comment "Quick Share mDNS"
sudo nft add rule inet filter input tcp dport 8765-8815 ct state new,established accept comment "Quick Share TCP"
```

---

## Installation & Usage

### 1. Build and Install via Automated Installer

The repository includes a comprehensive installer (`install.sh`) and standard `Makefile` that install the binary, register the `.desktop` launcher, install scalable application icons, set up systemd services, and configure the firewall:

#### System-Wide Installation (Recommended)
Installs to `/usr/local/bin`, installs `.desktop` launcher into `/usr/local/share/applications`, and configures the system firewall:
```bash
git clone https://github.com/adityatr64/QShare-linux.git
cd QShare-linux
cargo build --release
sudo ./install.sh
```

Or using `make`:
```bash
make
sudo make install
```

#### User-Mode Installation (No Root Required)
Installs into `~/.local/bin` and `~/.local/share/applications`:
```bash
./install.sh --user
```

#### Uninstallation
To cleanly remove all installed binaries, desktop launchers, and systemd services:
```bash
sudo ./install.sh --uninstall
```

### 2. Desktop Runner Integration

Once installed, Quick Share is fully indexed by your desktop environment's application runner:
- GNOME Shell: Press Super, type "Quick Share", and press Enter.
- KDE Plasma: Open KRunner (Alt+Space), type "Quick Share", and launch.
- Window Managers (Sway, Hyprland, i3): Appears in Rofi, Wofi, and dmenu.

### 3. Diagnostic and Network Verification

Before initiating transfers, you can verify your local network readiness using the built-in diagnostic tool:
```bash
QShare-linux --check-network
```

This checks:
- Local subnet IP address resolution
- TCP port 8765 availability
- Avahi mDNS service daemon status
- Bluetooth daemon status
- Active firewall state

### 4. Running as a Headless Daemon

For servers, NAS devices, or headless setups:
```bash
QShare-linux --headless --name "Linux Storage" --port 8765 --download-dir /mnt/storage/transfers
```

### 5. Running as a systemd User Service

Run Quick Share continuously in the background upon user login:
```bash
# Enable and start service
systemctl --user daemon-reload
systemctl --user enable --now qshare-linux.service

# View status and live transfer logs
systemctl --user status qshare-linux.service
journalctl --user -u qshare-linux.service -f
```

### 6. Command-Line Direct Send Mode

Transmit files directly to a specific target IP without opening the graphical interface:
```bash
QShare-linux --target 192.168.1.150:53601 --send /path/to/document.pdf /path/to/archive.tar.gz
```

---

## Troubleshooting

### Device Does Not Appear in Android Share Sheet
1. Run network diagnostics:
   ```bash
   QShare-linux --check-network
   ```
2. Verify Avahi daemon is active and broadcasting:
   ```bash
   sudo systemctl status avahi-daemon
   avahi-browse -rt _FC9F5ED42C8A._tcp
   ```
3. Verify Bluetooth is powered on and advertising:
   ```bash
   bluetoothctl show
   ```
4. Ensure both devices are connected to the same Wi-Fi subnet and client isolation is disabled on your router.
5. Verify port 5353 UDP is not blocked by your host firewall.

### Transfer Times Out During PIN Verification
1. Ensure the port range `8765:8815/tcp` is open in your firewall:
   ```bash
   sudo ./scripts/setup-firewall.sh
   ```
2. Confirm that the 4-digit verification PIN matches identically on both screens.
3. If using a custom port in settings, ensure that port is within the firewall's allowed range.

### Android Reports Transfer Declined Immediately
1. Inspect the terminal log output (`RUST_LOG=debug QShare-linux`).
2. Verify that the destination download folder exists and has write permissions.
3. On Android, verify visibility is set to "Visible to Everyone" or "Everyone for 10 minutes" rather than "Contacts Only".

---

## License & Upstream Contribution Note

This project is licensed under the MIT License. See [LICENSE](LICENSE) for complete details.

Contributions, bug reports, and pull requests are welcomed. If you identify discrepancies with upstream Android releases, packet framing variations on newer OEM skins (One UI, MIUI, OxygenOS), or edge cases in the UKEY2 state machine, please submit an issue with sanitized packet dumps and trace logs.
