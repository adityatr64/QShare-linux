use crate::events::DiscoveredPeer;
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
    pub qr_connect_btn: gtk::Button,
    pub peers_box: gtk::Box,
    pub peers_placeholder: adw::StatusPage,
    pub discovered_peers: Rc<RefCell<HashMap<String, (DiscoveredPeer, gtk::Box)>>>,
    pub send_callbacks: Rc<RefCell<Vec<Box<dyn Fn(DiscoveredPeer, Vec<PathBuf>) + 'static>>>>,
}

impl SendView {
    pub fn new() -> Self {
        let page = adw::PreferencesPage::new();

        let staged_files = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
        let discovered_peers = Rc::new(RefCell::new(HashMap::<String, (DiscoveredPeer, gtk::Box)>::new()));
        let send_callbacks = Rc::new(RefCell::new(Vec::new()));

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
        peers_group.set_description(Some("Devices on the same network running Quick Share or Nearby Share"));

        let peer_header_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        peer_header_actions.set_margin_top(4);
        peer_header_actions.set_margin_bottom(4);

        let qr_connect_btn = gtk::Button::builder()
            .label("Connect via QR / Direct IP")
            .icon_name("camera-photo-symbolic")
            .build();
        qr_connect_btn.add_css_class("flat");
        peer_header_actions.append(&qr_connect_btn);
        peers_group.add(&peer_header_actions);

        let peers_box = gtk::Box::new(gtk::Orientation::Vertical, 6);

        let peers_placeholder = adw::StatusPage::builder()
            .title("Scanning for Devices...")
            .description("Make sure the receiving device has Quick Share or Nearby Share turned on and visible")
            .icon_name("network-wireless-symbolic")
            .build();
        peers_placeholder.set_height_request(160);

        peers_group.add(&peers_placeholder);
        peers_group.add(&peers_box);
        page.add(&peers_group);

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
            qr_connect_btn,
            peers_box,
            peers_placeholder,
            discovered_peers,
            send_callbacks,
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
        if peers.contains_key(&peer.id) {
            return;
        }

        self.peers_placeholder.set_visible(false);

        let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        row.add_css_class("card");
        row.set_margin_top(4);
        row.set_margin_bottom(4);
        row.set_margin_start(4);
        row.set_margin_end(4);

        let icon = gtk::Image::from_icon_name(peer.device_type.icon_name());
        icon.set_icon_size(gtk::IconSize::Large);
        icon.set_margin_start(12);

        let details = gtk::Box::new(gtk::Orientation::Vertical, 2);
        details.set_hexpand(true);
        details.set_valign(gtk::Align::Center);

        let name_label = gtk::Label::new(Some(&peer.name));
        name_label.set_halign(gtk::Align::Start);
        name_label.add_css_class("heading");

        let sub_label = gtk::Label::new(Some(&format!("{}:{} ({})", peer.ip, peer.port, peer.id)));
        sub_label.set_halign(gtk::Align::Start);
        sub_label.add_css_class("caption");
        sub_label.add_css_class("dim-label");

        details.append(&name_label);
        details.append(&sub_label);

        let send_btn = gtk::Button::builder()
            .label("Send")
            .icon_name("mail-send-symbolic")
            .valign(gtk::Align::Center)
            .margin_end(12)
            .build();
        send_btn.add_css_class("suggested-action");

        let peer_clone = peer.clone();
        let staged_ref = self.staged_files.clone();
        let callbacks_ref = self.send_callbacks.clone();

        send_btn.connect_clicked(move |_| {
            let files = staged_ref.borrow().clone();
            for cb in callbacks_ref.borrow().iter() {
                cb(peer_clone.clone(), files.clone());
            }
        });

        row.append(&icon);
        row.append(&details);
        row.append(&send_btn);

        self.peers_box.append(&row);
        peers.insert(peer.id.clone(), (peer, row));
    }

    pub fn remove_peer(&self, id: &str) {
        let mut peers = self.discovered_peers.borrow_mut();
        if let Some((_, row)) = peers.remove(id) {
            self.peers_box.remove(&row);
        }
        if peers.is_empty() {
            self.peers_placeholder.set_visible(true);
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
