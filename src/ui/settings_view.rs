use crate::config::AppConfig;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

pub struct SettingsView {
    pub page: adw::PreferencesPage,
    pub name_entry: adw::EntryRow,
    pub download_row: adw::ActionRow,
    pub download_path_label: gtk::Label,
    pub change_folder_btn: gtk::Button,
    pub port_entry: adw::EntryRow,
    pub save_btn: gtk::Button,
    pub ip_row: adw::ActionRow,
    pub current_download_dir: Rc<RefCell<PathBuf>>,
    pub save_callbacks: Rc<RefCell<Vec<Box<dyn Fn(AppConfig) + 'static>>>>,
}

impl SettingsView {
    pub fn new(default_name: &str, default_download: PathBuf, default_port: u16, local_ip: &str) -> Self {
        let page = adw::PreferencesPage::new();

        let current_download_dir = Rc::new(RefCell::new(default_download.clone()));
        let save_callbacks: Rc<RefCell<Vec<Box<dyn Fn(AppConfig) + 'static>>>> = Rc::new(RefCell::new(Vec::new()));

        // ================= 1. Device Identity & Preferences =================
        let identity_group = adw::PreferencesGroup::new();
        identity_group.set_title("Device Identity and Preferences");
        identity_group.set_description(Some("Configure device identity and destination folder. Settings persist in ~/.config/quickshare/settings.json"));

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

        let download_path_label = gtk::Label::new(Some(&*default_download.to_string_lossy()));

        let change_folder_btn = gtk::Button::builder()
            .label("Change...")
            .valign(gtk::Align::Center)
            .build();
        change_folder_btn.add_css_class("flat");
        download_row.add_suffix(&change_folder_btn);

        identity_group.add(&download_row);

        // Config file location row
        let config_path = AppConfig::config_file_path();
        let config_row = adw::ActionRow::builder()
            .title("Configuration File Location")
            .subtitle(&*config_path.to_string_lossy())
            .build();
        let config_icon = gtk::Image::from_icon_name("document-properties-symbolic");
        config_row.add_prefix(&config_icon);
        identity_group.add(&config_row);

        // Save Button row
        let save_btn = gtk::Button::builder()
            .label("Save Changes")
            .icon_name("emblem-ok-symbolic")
            .valign(gtk::Align::Center)
            .halign(gtk::Align::End)
            .margin_top(8)
            .margin_bottom(8)
            .margin_end(12)
            .build();
        save_btn.add_css_class("suggested-action");

        let save_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        save_row.set_halign(gtk::Align::End);
        save_row.append(&save_btn);
        identity_group.add(&save_row);

        page.add(&identity_group);

        // Connect Save Button
        let name_entry_clone = name_entry.clone();
        let port_entry_clone = port_entry.clone();
        let download_dir_clone = current_download_dir.clone();
        let save_callbacks_clone = save_callbacks.clone();

        save_btn.connect_clicked(move |_| {
            let dev_name = name_entry_clone.text().to_string();
            let port_str = port_entry_clone.text().to_string();
            let port_val = port_str.trim().parse::<u16>().unwrap_or(8765);
            let down_dir = download_dir_clone.borrow().clone();

            let cfg = AppConfig {
                device_name: if dev_name.trim().is_empty() {
                    "Linux Quick Share".to_string()
                } else {
                    dev_name.trim().to_string()
                },
                download_dir: down_dir,
                port: port_val,
            };

            if let Err(e) = cfg.save() {
                tracing::error!("Failed to save settings to disk: {:?}", e);
            } else {
                tracing::info!("Settings successfully saved to {}", AppConfig::config_file_path().display());
            }

            for cb in save_callbacks_clone.borrow().iter() {
                cb(cfg.clone());
            }
        });

        // ================= 2. Network & Service =================
        let network_group = adw::PreferencesGroup::new();
        network_group.set_title("Network and Service");

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

        page.add(&network_group);

        // ================= 3. Cryptography & Protocol =================
        let proto_group = adw::PreferencesGroup::new();
        proto_group.set_title("Security and Protocol Architecture");
        proto_group.set_description(Some("Reconstructed from Nearby Share binary reverse-engineering"));

        let ukey2_row = adw::ActionRow::builder()
            .title("UKEY2 Key Exchange")
            .subtitle("Curve25519 Diffie-Hellman + SHA-512 Commitment + Modulo-9973 PIN Verification")
            .build();
        let lock_icon = gtk::Image::from_icon_name("channel-secure-symbolic");
        ukey2_row.add_prefix(&lock_icon);
        proto_group.add(&ukey2_row);

        let enc_row = adw::ActionRow::builder()
            .title("Wire Framing and Encryption")
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

        page.add(&proto_group);

        Self {
            page,
            name_entry,
            download_row,
            download_path_label,
            change_folder_btn,
            port_entry,
            save_btn,
            ip_row,
            current_download_dir,
            save_callbacks,
        }
    }

    pub fn on_save(&self, callback: impl Fn(AppConfig) + 'static) {
        self.save_callbacks.borrow_mut().push(Box::new(callback));
    }

    pub fn get_device_name(&self) -> String {
        self.name_entry.text().to_string()
    }

    pub fn set_download_path(&self, path: PathBuf) {
        let display = path.to_string_lossy().to_string();
        self.download_row.set_subtitle(&display);
        self.download_path_label.set_text(&display);
        *self.current_download_dir.borrow_mut() = path.clone();

        // Automatically persist download directory change to disk
        let dev_name = self.name_entry.text().to_string();
        let port_val = self.port_entry.text().trim().parse::<u16>().unwrap_or(8765);
        let cfg = AppConfig {
            device_name: if dev_name.trim().is_empty() {
                "Linux Quick Share".to_string()
            } else {
                dev_name.trim().to_string()
            },
            download_dir: path,
            port: port_val,
        };

        if let Err(e) = cfg.save() {
            tracing::error!("Failed to save updated download path: {:?}", e);
        } else {
            tracing::info!("Download path saved to {}", AppConfig::config_file_path().display());
        }

        for cb in self.save_callbacks.borrow().iter() {
            cb(cfg.clone());
        }
    }
}
