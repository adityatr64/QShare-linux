use crate::events::DiscoveredPeer;
use crate::ui::transfer_card::TransferCard;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

pub struct ReceiveView {
    pub page: adw::PreferencesPage,
    pub visibility_switch: adw::SwitchRow,
    pub peers_group: adw::PreferencesGroup,
    pub peers_placeholder: adw::ActionRow,
    pub discovered_peer_rows: Rc<RefCell<HashMap<String, (Rc<RefCell<DiscoveredPeer>>, adw::ActionRow)>>>,
    pub empty_placeholder: adw::StatusPage,
    pub transfers_box: gtk::Box,
    pub active_transfers: Rc<RefCell<HashMap<u64, TransferCard>>>,
    pub send_peer_callbacks: Rc<RefCell<Vec<Box<dyn Fn(DiscoveredPeer) + 'static>>>>,
    pub cancel_callbacks: Rc<RefCell<Vec<Box<dyn Fn(u64) + 'static>>>>,
}

impl ReceiveView {
    pub fn new(device_name: &str, endpoint_id: &str, port: u16, local_ip: &str) -> Self {
        let page = adw::PreferencesPage::new();

        // 1. Device Discovery Preferences Group
        let vis_group = adw::PreferencesGroup::new();
        vis_group.set_title("Quick Share Discovery Status");
        vis_group.set_description(Some(
            "Actively broadcasting via Bluetooth LE (0xFEF3) and Wi-Fi LAN mDNS (_FC9F5ED42C8A)"
        ));

        let visibility_switch = adw::SwitchRow::builder()
            .title("Visible to Everyone")
            .subtitle("Nearby Android and PC devices can discover and send files to this device")
            .active(true)
            .build();
        vis_group.add(&visibility_switch);

        let dev_row = adw::ActionRow::builder()
            .title("Device Name")
            .subtitle(device_name)
            .build();
        let dev_icon = gtk::Image::from_icon_name("computer-symbolic");
        dev_row.add_prefix(&dev_icon);
        vis_group.add(&dev_row);

        // Fixed: Use "and" instead of "&" to prevent Pango markup parsing warning
        let ep_row = adw::ActionRow::builder()
            .title("Endpoint ID and Listening Address")
            .subtitle(&format!("ID: {} | {}:{}", endpoint_id, local_ip, port))
            .build();
        let ep_icon = gtk::Image::from_icon_name("network-wireless-symbolic");
        ep_row.add_prefix(&ep_icon);
        vis_group.add(&ep_row);

        page.add(&vis_group);

        // 2. Discovered Nearby Devices Group
        let peers_group = adw::PreferencesGroup::new();
        peers_group.set_title("Discovered Nearby Devices");
        peers_group.set_description(Some(
            "Active Quick Share peers detected over Bluetooth LE and local network"
        ));

        let peers_placeholder = adw::ActionRow::builder()
            .title("Scanning for nearby devices...")
            .subtitle("Ensure your mobile device has Quick Share visible to Everyone")
            .build();
        let scan_icon = gtk::Image::from_icon_name("network-wireless-symbolic");
        peers_placeholder.add_prefix(&scan_icon);
        peers_group.add(&peers_placeholder);
        page.add(&peers_group);

        // 3. Active / Recent Transfers Area
        let trans_group = adw::PreferencesGroup::new();
        trans_group.set_title("Transfers");
        trans_group.set_description(Some("Live transfer progress and transmission statistics"));

        let transfers_box = gtk::Box::new(gtk::Orientation::Vertical, 6);

        let empty_placeholder = adw::StatusPage::builder()
            .title("Ready to Receive")
            .description("Open Quick Share or Nearby Share on your mobile device to transfer files directly to this PC")
            .icon_name("folder-download-symbolic")
            .build();
        empty_placeholder.set_height_request(160);

        trans_group.add(&empty_placeholder);
        trans_group.add(&transfers_box);
        page.add(&trans_group);

        Self {
            page,
            visibility_switch,
            peers_group,
            peers_placeholder,
            discovered_peer_rows: Rc::new(RefCell::new(HashMap::new())),
            empty_placeholder,
            transfers_box,
            active_transfers: Rc::new(RefCell::new(HashMap::new())),
            send_peer_callbacks: Rc::new(RefCell::new(Vec::new())),
            cancel_callbacks: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn on_send_to_peer(&self, callback: impl Fn(DiscoveredPeer) + 'static) {
        self.send_peer_callbacks.borrow_mut().push(Box::new(callback));
    }

    pub fn add_peer(&self, peer: DiscoveredPeer) {
        let mut rows = self.discovered_peer_rows.borrow_mut();

        // Deduplicate by ID or IP
        let existing_key = rows.iter().find_map(|(id, (existing, _))| {
            let cur = existing.borrow();
            if id == &peer.id || cur.ip == peer.ip {
                Some(id.clone())
            } else {
                None
            }
        });

        if let Some(key) = existing_key {
            if let Some((existing_rc, row)) = rows.remove(&key) {
                let (final_name, final_type) = {
                    let cur = existing_rc.borrow();
                    let name = if peer.name.starts_with("Quick Share Device") && !cur.name.starts_with("Quick Share Device") {
                        cur.name.clone()
                    } else {
                        peer.name.clone()
                    };
                    let dev_type = if peer.device_type == crate::events::DeviceType::Unknown && cur.device_type != crate::events::DeviceType::Unknown {
                        cur.device_type
                    } else {
                        peer.device_type
                    };
                    (name, dev_type)
                };
                let mut updated_peer = peer.clone();
                updated_peer.name = final_name;
                updated_peer.device_type = final_type;

                *existing_rc.borrow_mut() = updated_peer.clone();
                row.set_title(&updated_peer.name);
                row.set_subtitle(&format!(
                    "{} • {}:{} [ID: {}]",
                    updated_peer.device_type.display_name(),
                    updated_peer.ip,
                    updated_peer.port,
                    updated_peer.id
                ));
                self.peers_placeholder.set_visible(false);
                rows.insert(updated_peer.id.clone(), (existing_rc, row));
                return;
            }
        }

        self.peers_placeholder.set_visible(false);

        let row = adw::ActionRow::builder()
            .title(&peer.name)
            .subtitle(&format!(
                "{} • {}:{} [ID: {}]",
                peer.device_type.display_name(),
                peer.ip,
                peer.port,
                peer.id
            ))
            .build();

        let icon = gtk::Image::from_icon_name(peer.device_type.icon_name());
        icon.set_icon_size(gtk::IconSize::Large);
        row.add_prefix(&icon);

        let send_btn = gtk::Button::builder()
            .label("Send Files")
            .icon_name("mail-send-symbolic")
            .valign(gtk::Align::Center)
            .build();
        send_btn.add_css_class("suggested-action");

        let peer_rc = Rc::new(RefCell::new(peer.clone()));
        let peer_rc_for_click = peer_rc.clone();
        let callbacks = self.send_peer_callbacks.clone();
        send_btn.connect_clicked(move |_| {
            let current = peer_rc_for_click.borrow().clone();
            for cb in callbacks.borrow().iter() {
                cb(current.clone());
            }
        });

        row.add_suffix(&send_btn);
        row.set_activatable_widget(Some(&send_btn));
        row.set_visible(true);

        self.peers_group.add(&row);
        rows.insert(peer.id.clone(), (peer_rc, row));
    }

    pub fn mark_peer_lost(&self, id: &str) {
        let rows = self.discovered_peer_rows.borrow();
        if let Some((peer_rc, row)) = rows.get(id) {
            let peer = peer_rc.borrow();
            row.set_subtitle(&format!(
                "{} • {}:{} (Last seen nearby)",
                peer.device_type.display_name(),
                peer.ip,
                peer.port
            ));
        }
    }

    pub fn on_cancel_transfer(&self, callback: impl Fn(u64) + 'static) {
        self.cancel_callbacks.borrow_mut().push(Box::new(callback));
    }

    pub fn on_transfer_started(&self, id: u64, filename: &str, total: u64, is_send: bool) {
        self.empty_placeholder.set_visible(false);
        let card = TransferCard::new(filename, total, is_send);
        let cancel_cbs = self.cancel_callbacks.clone();
        card.on_cancel(move || {
            for cb in cancel_cbs.borrow().iter() {
                cb(id);
            }
        });
        self.transfers_box.prepend(&card.container);
        self.active_transfers.borrow_mut().insert(id, card);
    }

    pub fn on_transfer_progress(&self, id: u64, transferred: u64, total: u64, speed_mbps: f64) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.update(transferred, total, speed_mbps);
        }
    }

    pub fn on_transfer_completed(&self, id: u64, file_path: Option<PathBuf>) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.complete(file_path);
        }
    }

    pub fn on_transfer_failed(&self, id: u64, err: &str) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.fail(err);
        }
    }
}
