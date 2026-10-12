use crate::events::DiscoveredPeer;
use crate::ui::transfer_card::TransferCard;
use gtk4::gdk;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

pub struct SendView {
    pub page: adw::PreferencesPage,
    pub staged_files: Rc<RefCell<Vec<PathBuf>>>,
    pub staged_box: gtk::Box,
    pub staged_placeholder: gtk::Label,
    pub add_files_btn: gtk::Button,
    pub clear_files_btn: gtk::Button,
    pub refresh_btn: gtk::Button,
    pub manual_ip_btn: gtk::Button,
    pub peers_group: adw::PreferencesGroup,
    pub peers_placeholder: adw::ActionRow,
    pub discovered_peers: Rc<RefCell<HashMap<String, (Rc<RefCell<DiscoveredPeer>>, adw::ActionRow)>>>,
    pub transfers_group: adw::PreferencesGroup,
    pub transfers_placeholder: adw::ActionRow,
    pub transfers_box: gtk::Box,
    pub active_transfers: Rc<RefCell<HashMap<u64, TransferCard>>>,
    pub send_callbacks: Rc<RefCell<Vec<Box<dyn Fn(DiscoveredPeer, Vec<PathBuf>) + 'static>>>>,
    pub cancel_callbacks: Rc<RefCell<Vec<Box<dyn Fn(u64) + 'static>>>>,
}

impl SendView {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let staged_files = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
        let discovered_peers = Rc::new(RefCell::new(HashMap::<String, (Rc<RefCell<DiscoveredPeer>>, adw::ActionRow)>::new()));
        let active_transfers = Rc::new(RefCell::new(HashMap::<u64, TransferCard>::new()));
        let send_callbacks = Rc::new(RefCell::new(Vec::new()));
        let cancel_callbacks = Rc::new(RefCell::new(Vec::new()));

        // ================= 1. Staged Files Section =================
        let stage_group = adw::PreferencesGroup::new();
        stage_group.set_title("Files to Share");
        stage_group.set_description(Some("Select files to share or drag and drop them directly into this area"));

        let stage_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
        stage_card.add_css_class("card");
        stage_card.set_margin_top(4);
        stage_card.set_margin_bottom(4);
        stage_card.set_margin_start(4);
        stage_card.set_margin_end(4);

        let buttons_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        buttons_row.set_margin_start(12);
        buttons_row.set_margin_end(12);
        buttons_row.set_margin_top(12);

        let add_files_btn = gtk::Button::builder()
            .label("Add Files")
            .icon_name("list-add-symbolic")
            .build();
        add_files_btn.add_css_class("suggested-action");

        let clear_files_btn = gtk::Button::builder()
            .label("Clear All")
            .icon_name("edit-delete-symbolic")
            .sensitive(false)
            .build();
        clear_files_btn.add_css_class("flat");

        buttons_row.append(&add_files_btn);
        buttons_row.append(&clear_files_btn);
        stage_card.append(&buttons_row);

        // Staged files container
        let staged_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        staged_box.set_margin_start(12);
        staged_box.set_margin_end(12);
        staged_box.set_margin_top(6);
        staged_box.set_margin_bottom(12);

        let staged_placeholder = gtk::Label::new(Some("Drag and drop files here, or click 'Add Files'"));
        staged_placeholder.set_margin_top(16);
        staged_placeholder.set_margin_bottom(16);
        staged_placeholder.add_css_class("dim-label");
        staged_box.append(&staged_placeholder);

        stage_card.append(&staged_box);
        stage_group.add(&stage_card);
        page.add(&stage_group);

        // ================= 2. Nearby Devices Section =================
        let peers_group = adw::PreferencesGroup::new();
        peers_group.set_title("Nearby Quick Share Targets");
        peers_group.set_description(Some("Devices discovered on Bluetooth LE or local network"));

        let peer_header_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        peer_header_actions.set_margin_top(4);
        peer_header_actions.set_margin_bottom(4);

        let refresh_btn = gtk::Button::builder()
            .label("Scan Nearby")
            .icon_name("view-refresh-symbolic")
            .build();
        refresh_btn.add_css_class("flat");
        peer_header_actions.append(&refresh_btn);

        let manual_ip_btn = gtk::Button::builder()
            .label("Add IP Address")
            .icon_name("network-server-symbolic")
            .build();
        manual_ip_btn.add_css_class("flat");
        peer_header_actions.append(&manual_ip_btn);
        peers_group.add(&peer_header_actions);

        let peers_placeholder = adw::ActionRow::builder()
            .title("Scanning for nearby devices...")
            .subtitle("Ensure Quick Share is open and visible to Everyone on your mobile device")
            .build();
        let scan_icon = gtk::Image::from_icon_name("network-wireless-symbolic");
        peers_placeholder.add_prefix(&scan_icon);
        peers_group.add(&peers_placeholder);

        page.add(&peers_group);

        // ================= 3. Transfers Section =================
        let transfers_group = adw::PreferencesGroup::new();
        transfers_group.set_title("Transfers");
        transfers_group.set_description(Some("Live transfer progress and transmission statistics"));

        let transfers_placeholder = adw::ActionRow::builder()
            .title("No Active Transfers")
            .subtitle("Select files and click Send next to a device to transmit")
            .build();
        let trans_icon = gtk::Image::from_icon_name("mail-send-symbolic");
        transfers_placeholder.add_prefix(&trans_icon);
        transfers_group.add(&transfers_placeholder);

        let transfers_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
        transfers_group.add(&transfers_box);
        page.add(&transfers_group);

        // Setup Drag & Drop controller on stage_card
        let drop_target = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let staged_files_clone = staged_files.clone();
        let staged_box_clone = staged_box.clone();
        let clear_btn_clone = clear_files_btn.clone();
        let placeholder_clone = staged_placeholder.clone();

        drop_target.connect_drop(move |_target, value, _x, _y| {
            if let Ok(file_list) = value.get::<gdk::FileList>() {
                let mut paths = Vec::new();
                for file in file_list.files() {
                    if let Some(path) = file.path() {
                        paths.push(path);
                    }
                }
                if !paths.is_empty() {
                    let mut staged = staged_files_clone.borrow_mut();
                    for path in paths {
                        if !staged.contains(&path) {
                            staged.push(path);
                        }
                    }
                    drop(staged);
                    refresh_staged_helper(
                        &staged_files_clone,
                        &staged_box_clone,
                        &clear_btn_clone,
                        &placeholder_clone,
                    );
                    return true;
                }
            }
            false
        });
        stage_card.add_controller(drop_target);

        Self {
            page,
            staged_files,
            staged_box,
            staged_placeholder,
            add_files_btn,
            clear_files_btn,
            refresh_btn,
            manual_ip_btn,
            peers_group,
            peers_placeholder,
            discovered_peers,
            transfers_group,
            transfers_placeholder,
            transfers_box,
            active_transfers,
            send_callbacks,
            cancel_callbacks,
        }
    }

    pub fn on_send(&self, callback: impl Fn(DiscoveredPeer, Vec<PathBuf>) + 'static) {
        self.send_callbacks.borrow_mut().push(Box::new(callback));
    }

    pub fn stage_files(&self, paths: Vec<PathBuf>) {
        let mut staged = self.staged_files.borrow_mut();
        for path in paths {
            if !staged.contains(&path) {
                staged.push(path);
            }
        }
        drop(staged);
        self.refresh_staged_ui();
    }

    pub fn clear_staged(&self) {
        self.staged_files.borrow_mut().clear();
        self.refresh_staged_ui();
    }

    fn refresh_staged_ui(&self) {
        refresh_staged_helper(
            &self.staged_files,
            &self.staged_box,
            &self.clear_files_btn,
            &self.staged_placeholder,
        );
    }

    pub fn add_peer(&self, peer: DiscoveredPeer) {
        let mut peers = self.discovered_peers.borrow_mut();

        // Deduplicate by ID or IP
        let existing_key = peers.iter().find_map(|(id, (existing, _))| {
            let cur = existing.borrow();
            if id == &peer.id || cur.ip == peer.ip {
                Some(id.clone())
            } else {
                None
            }
        });

        if let Some(key) = existing_key {
            if let Some((existing_rc, row)) = peers.remove(&key) {
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
                peers.insert(updated_peer.id.clone(), (existing_rc, row));
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
            .label("Send")
            .icon_name("mail-send-symbolic")
            .valign(gtk::Align::Center)
            .build();
        send_btn.add_css_class("suggested-action");

        let peer_rc = Rc::new(RefCell::new(peer.clone()));
        let peer_rc_for_click = peer_rc.clone();
        let staged_ref = self.staged_files.clone();
        let callbacks_ref = self.send_callbacks.clone();

        send_btn.connect_clicked(move |_| {
            let files = staged_ref.borrow().clone();
            if files.is_empty() {
                return;
            }
            let current = peer_rc_for_click.borrow().clone();
            for cb in callbacks_ref.borrow().iter() {
                cb(current.clone(), files.clone());
            }
        });

        row.add_suffix(&send_btn);
        row.set_activatable_widget(Some(&send_btn));
        row.set_visible(true);

        self.peers_group.add(&row);
        peers.insert(peer.id.clone(), (peer_rc, row));
    }

    pub fn mark_peer_lost(&self, id: &str) {
        let peers = self.discovered_peers.borrow();
        if let Some((peer_rc, row)) = peers.get(id) {
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

    pub fn on_transfer_started(&self, id: u64, filename: &str, total: u64) {
        self.transfers_placeholder.set_visible(false);
        let card = TransferCard::new(filename, total, true);
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

fn refresh_staged_helper(
    staged_files: &Rc<RefCell<Vec<PathBuf>>>,
    staged_box: &gtk::Box,
    clear_files_btn: &gtk::Button,
    staged_placeholder: &gtk::Label,
) {
    while let Some(child) = staged_box.first_child() {
        staged_box.remove(&child);
    }

    let staged = staged_files.borrow();
    let has_files = !staged.is_empty();
    clear_files_btn.set_sensitive(has_files);

    if !has_files {
        staged_box.append(staged_placeholder);
        return;
    }

    for (idx, path) in staged.iter().enumerate() {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.add_css_class("card");
        row.set_margin_top(2);
        row.set_margin_bottom(2);
        row.set_margin_start(4);
        row.set_margin_end(4);

        let icon = gtk::Image::from_icon_name("text-x-generic-symbolic");
        icon.set_margin_start(8);

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown File".to_string());
        let size = std::fs::metadata(path)
            .map(|m| format!("{:.2} MB", m.len() as f64 / 1_048_576.0))
            .unwrap_or_else(|_| "0 MB".to_string());

        let name_label = gtk::Label::new(Some(&name));
        name_label.set_halign(gtk::Align::Start);
        name_label.set_hexpand(true);

        let size_label = gtk::Label::new(Some(&size));
        size_label.add_css_class("dim-label");

        let remove_btn = gtk::Button::from_icon_name("window-close-symbolic");
        remove_btn.add_css_class("flat");
        remove_btn.set_margin_end(4);

        let staged_ref = staged_files.clone();
        let staged_box_clone = staged_box.clone();
        let clear_btn_clone = clear_files_btn.clone();
        let placeholder_clone = staged_placeholder.clone();

        remove_btn.connect_clicked(move |_| {
            let mut files = staged_ref.borrow_mut();
            if idx < files.len() {
                files.remove(idx);
            }
            drop(files);
            refresh_staged_helper(
                &staged_ref,
                &staged_box_clone,
                &clear_btn_clone,
                &placeholder_clone,
            );
        });

        row.append(&icon);
        row.append(&name_label);
        row.append(&size_label);
        row.append(&remove_btn);
        staged_box.append(&row);
    }
}
