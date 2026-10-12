use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

pub struct SettingsView {
    pub container: gtk::Box,
    pub name_entry: adw::EntryRow,
    pub download_row: adw::ActionRow,
    pub download_path_label: gtk::Label,
    pub change_folder_btn: gtk::Button,
    pub port_entry: adw::EntryRow,
    pub ip_row: adw::ActionRow,
    pub current_download_dir: Rc<RefCell<PathBuf>>,
}

impl SettingsView {
    pub fn new(default_name: &str, default_download: PathBuf, default_port: u16, local_ip: &str) -> Self {
        let container = gtk::Box::new(gtk::Orientation::Vertical, 16);
        container.set_margin_start(16);
        container.set_margin_end(16);
        container.set_margin_top(16);
        container.set_margin_bottom(16);

        let current_download_dir = Rc::new(RefCell::new(default_download.clone()));

        // ================= 1. Device Identity =================
        let identity_group = adw::PreferencesGroup::new();
        identity_group.set_title("Device Identity");
        identity_group.set_description(Some("Configure how this computer appears to other Quick Share devices"));

        let name_entry = adw::EntryRow::builder()
            .title("Device Name")
            .text(default_name)
            .build();
        identity_group.add(&name_entry);

        let port_entry = adw::EntryRow::builder()
            .title("Listening Port")
            .text(&default_port.to_string())
            .build();
        identity_group.add(&port_entry);

        // Download Directory Row
        let download_row = adw::ActionRow::builder()
            .title("Download Destination")
            .subtitle(&*default_download.to_string_lossy())
            .build();

        let download_path_label = gtk::Label::new(Some(&default_download.to_string_lossy()));

        let change_folder_btn = gtk::Button::builder()
            .label("Change...")
            .valign(gtk::Align::Center)
            .build();
        change_folder_btn.add_css_class("flat");
        download_row.add_suffix(&change_folder_btn);

        identity_group.add(&download_row);
        container.append(&identity_group);

        // ================= 2. Network & Service =================
        let network_group = adw::PreferencesGroup::new();
        network_group.set_title("Network & Service");

        let ip_row = adw::ActionRow::builder()
            .title("Local IP Address")
            .subtitle(local_ip)
            .build();
        let ip_icon = gtk::Image::from_icon_name("network-wired-symbolic");
        ip_row.add_prefix(&ip_icon);
        network_group.add(&ip_row);

        let mdns_row = adw::ActionRow::builder()
            .title("mDNS Service Identifier")
            .subtitle("_FC9F5ED42C8A._tcp.local. (SHA256(\"NearbySharing\"))")
            .build();
        let mdns_icon = gtk::Image::from_icon_name("network-workgroup-symbolic");
        mdns_row.add_prefix(&mdns_icon);
        network_group.add(&mdns_row);

        container.append(&network_group);

        // ================= 3. Cryptography & Protocol =================
        let proto_group = adw::PreferencesGroup::new();
        proto_group.set_title("Security & Protocol Architecture");
        proto_group.set_description(Some("Reconstructed from Nearby Share binary reverse-engineering"));

        let ukey2_row = adw::ActionRow::builder()
            .title("UKEY2 Key Exchange")
            .subtitle("Curve25519 Diffie-Hellman + SHA-512 Commitment + Modulo-9973 PIN Verification")
            .build();
        let lock_icon = gtk::Image::from_icon_name("channel-secure-symbolic");
        ukey2_row.add_prefix(&lock_icon);
        proto_group.add(&ukey2_row);

        let enc_row = adw::ActionRow::builder()
            .title("Wire Framing & Encryption")
            .subtitle("AES-256-CBC Ciphertext + HMAC-SHA256 Authenticated SecureMessage Envelope")
            .build();
        let enc_icon = gtk::Image::from_icon_name("security-high-symbolic");
        enc_row.add_prefix(&enc_icon);
        proto_group.add(&enc_row);

        let proto_row = adw::ActionRow::builder()
            .title("Protobuf Specification")
            .subtitle("quickshare_wire.proto compiled with Prost")
            .build();
        let doc_icon = gtk::Image::from_icon_name("text-x-generic-symbolic");
        proto_row.add_prefix(&doc_icon);
        proto_group.add(&proto_row);

        container.append(&proto_group);

        Self {
            container,
            name_entry,
            download_row,
            download_path_label,
            change_folder_btn,
            port_entry,
            ip_row,
            current_download_dir,
        }
    }

    pub fn get_device_name(&self) -> String {
        self.name_entry.text().to_string()
    }

    pub fn set_download_path(&self, path: PathBuf) {
        let display = path.to_string_lossy().to_string();
        self.download_row.set_subtitle(&display);
        self.download_path_label.set_text(&display);
        *self.current_download_dir.borrow_mut() = path;
    }
}
