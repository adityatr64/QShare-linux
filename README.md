# Quick Share Native Desktop Client & Receiver

An interoperable, native Linux desktop application and receiver daemon for **Google Quick Share / Nearby Share**, built in Rust with **GTK4 / Libadwaita**, async **Tokio**, bidirectional file transfers, UKEY2 security handshake, Bluetooth LE discovery, and mDNS.

---

## 🌟 Key Features

1. **Native GNOME / Libadwaita Interface**:
   - Clean 3-tab layout: **Receive**, **Send**, and **Settings**.
   - Built with Libadwaita 1.4+ styling, `adw::ViewStack`, `adw::ViewSwitcher`, and native `adw::ToastOverlay`.

2. **Bidirectional File Transfer**:
   - **Receive Mode**:
     * mDNS advertiser (`_FC9F5ED42C8A._tcp.local.`) announces device visibility.
     * Visibility toggle: **"Visible to Everyone"** vs **"Off (Hidden)"**.
     * Mutual authentication transfer confirmation modal showing: sender name, file list, total size, and the **4-digit UKEY2 PIN**.
     * Real-time transfer cards showing filename, transfer speed (MB/s), progress bar, and completion badges.
     * Incoming files stream directly into `~/Downloads/`.
   - **Send Mode**:
     * Drag-and-drop file staging area + native file picker.
     * Dynamic list of discovered nearby targets with device type icons (`phone-symbolic`, `tablet-symbolic`, `computer-symbolic`).
     * Direct **"Send"** trigger streaming 64 KB chunks over encrypted transport upon peer acceptance.

3. **Bluetooth LE & Wi-Fi LAN Discovery**:
   - **Bluetooth LE Advertisement (`0xFEF3`)**: Implements the official Google Nearby Connections BLE beacon carrying the 4-byte endpoint ID, service ID hash (`[0xFC, 0x9F, 0x5E]`), and device metadata. This allows Android phones to detect the Linux workstation in their Quick Share share sheet immediately without scanning Wi-Fi continuously.
   - **DNS-SD / mDNS Registration**: Broadcasts `_FC9F5ED42C8A._tcp.local.` with RFC-compliant 8-byte base64 instance name and `n=<endpoint_info>` TXT record matching Android's `WifiLanServiceInfo` parser.
   - **Active Peer Discovery**: Scans both Bluetooth LE and local subnet neighbors (`ip neigh`) for active Quick Share targets.

4. **Cryptographic Integrity & Security**:
   - **UKEY2 Key Exchange**: Curve25519 Diffie-Hellman + SHA-512 commitment.
   - **Authentic Modulo-9973 PIN**: Reconstructed from the Quick Share binary disassembly (`0x1404E2160`).
   - **Authenticated Framing**: AES-256-CBC encryption wrapped in HMAC-SHA256 authenticated `SecureMessage` envelopes.
   - **Protobuf Schemas**: Compiled from [quickshare_wire.proto](file:///home/wiz/quickshare-analysis/quickshare_wire.proto).

---

## 📦 System Prerequisites

```bash
# Arch Linux
sudo pacman -S --needed libadwaita gtk4 gdk-pixbuf2 avahi protobuf

# Ubuntu / Debian
sudo apt-get install -y libadwaita-1-dev libgtk-4-dev libgdk-pixbuf-2.0-dev avahi-daemon protobuf-compiler

# Fedora
sudo dnf install -y libadwaita-devel gtk4-devel gdk-pixbuf2-devel avahi protobuf-compiler
```

---

## 🚀 Building & Running

### 1. Build

```bash
cd quickshare-receiver
cargo build --release
```

The compiled release binary is located at `target/release/quickshare-receiver`.

### 2. Run Desktop GUI (Default)

Launch the native Libadwaita desktop graphical client:

```bash
./target/release/quickshare-receiver
```

Or customize initial parameters:

```bash
./target/release/quickshare-receiver --name "My Linux Workstation" --port 8765 --download-dir ~/Downloads
```

### 3. Run Headless / Terminal Daemon Mode

If running on a headless server without a display server:

```bash
./target/release/quickshare-receiver --headless --name "Server Receiver" --port 8765
```

### 4. CLI Direct Send Mode

Send files directly from the command line:

```bash
./target/release/quickshare-receiver --target 192.168.1.50:8765 --send ~/Documents/report.pdf ~/Photos/photo.jpg
```

---

## 🧪 Testing & Verification

Run the integration test suite:

```bash
cargo test
```

Tests verify:
- End-to-end UKEY2 client-server key exchange and matching 4-digit PIN generation.
- Full bidirectional AES-256-CBC and HMAC-SHA256 secure frame exchange.
- Complete wire protocol handshake: `ConnectionRequest` -> `ConnectionResponse` -> `PairedKeyEncryption` -> `IntroductionFrame` -> `SharingResponse` -> chunk transfer.
- QR pairing URI generation, JSON parser, and Pixbuf rendering.

---

## 📁 Architecture Overview

```
quickshare-receiver/
├── Cargo.toml                # Dependencies: libadwaita, gtk4, qrcode, tokio, prost, dalek
├── build.rs                  # Compiles quickshare_wire.proto using prost-build
├── tests/
│   └── transfer_test.rs      # UKEY2, QR, and wire protocol exchange integration tests
└── src/
    ├── lib.rs                # Library crate exports for testing and external consumers
    ├── main.rs               # Libadwaita Application entry point, Tokio runtime orchestration
    ├── proto.rs              # Prost Protobuf bindings generated from quickshare_wire.proto
    ├── crypto.rs             # UKEY2 Curve25519, HKDF, Modulo 9973 PIN, AES-CBC & HMAC
    ├── ukey2.rs              # Client and Server UKEY2 handshake state machines
    ├── secure_frame.rs       # Authenticated SecureMessage encryption / decryption
    ├── transport.rs          # 4-byte BE length-prefixed async I/O
    ├── discovery.rs          # mDNS advertiser and browser for _FC9F5ED42C8A._tcp.local.
    ├── events.rs             # UI and background thread AppEvent definitions
    ├── qr.rs                 # QR code bootstrap parser and Pixbuf generator
    ├── receiver.rs/session.rs # Incoming transfer session with live progress and PIN modal
    ├── sender.rs             # Outgoing transfer client pipeline
    └── ui/
        ├── mod.rs
        ├── window.rs         # MainWindow, ViewStack, ToastOverlay, PIN confirmation modal
        ├── receive_view.rs   # Visibility switch, QR Code presentation tile, live progress cards
        ├── send_view.rs      # File staging area, discovered nearby targets list, Send trigger
        └── settings_view.rs  # Device name, downloads directory picker, crypto specs
```
