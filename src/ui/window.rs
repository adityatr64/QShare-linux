use crate::events::{AppEvent, DeviceType, DiscoveredPeer};
use crate::ui::receive_view::ReceiveView;
use crate::ui::send_view::SendView;
use crate::ui::settings_view::SettingsView;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use tokio::sync::oneshot;

pub struct MainWindow {
    pub window: adw::ApplicationWindow,
    pub toast_overlay: adw::ToastOverlay,
    pub receive_view: Rc<ReceiveView>,
    pub send_view: Rc<SendView>,
    pub settings_view: Rc<SettingsView>,
}

impl MainWindow {
    pub fn new(
        app: &adw::Application,
        device_name: &str,
        download_dir: PathBuf,
        port: u16,
        local_ip: &str,
        endpoint_id: &str,
    ) -> Self {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Quick Share")
            .default_width(800)
            .default_height(700)
            .build();

        let toast_overlay = adw::ToastOverlay::new();

        // Header Bar
        let header_bar = adw::HeaderBar::new();

        // View Stack
        let view_stack = adw::ViewStack::new();
        view_stack.set_vexpand(true);
        view_stack.set_hexpand(true);

        // 1. Receive View
        let receive_view = Rc::new(ReceiveView::new(device_name, endpoint_id, port, local_ip));
        view_stack.add_titled_with_icon(
            &receive_view.page,
            Some("receive"),
            "Receive",
            "folder-download-symbolic",
        );

        // 2. Send View
        let send_view = Rc::new(SendView::new());
        view_stack.add_titled_with_icon(
            &send_view.page,
            Some("send"),
            "Send",
            "mail-send-symbolic",
        );

        // 3. Settings View
        let settings_view = Rc::new(SettingsView::new(
            device_name,
            download_dir,
            port,
            local_ip,
        ));
        view_stack.add_titled_with_icon(
            &settings_view.page,
            Some("settings"),
            "Settings",
            "emblem-system-symbolic",
        );

        // Ensure Receive view is visible by default
        view_stack.set_visible_child_name("receive");

        // View Switcher in HeaderBar
        let view_switcher = adw::ViewSwitcher::builder()
            .stack(&view_stack)
            .policy(adw::ViewSwitcherPolicy::Wide)
            .build();
        header_bar.set_title_widget(Some(&view_switcher));

        // Use ToolbarView to properly dock HeaderBar and expand ViewStack content
        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&header_bar);
        toolbar_view.set_content(Some(&view_stack));

        toast_overlay.set_child(Some(&toolbar_view));
        window.set_content(Some(&toast_overlay));

        // Inject application-wide custom styles for modern Libadwaita transfer cards and PIN badge
        let css_provider = gtk::CssProvider::new();
        css_provider.load_from_data(
            r#"
            .transfer-card {
                background-color: @card_bg_color;
                border: 1px solid alpha(@card_fg_color, 0.12);
                border-radius: 12px;
                padding: 12px 14px;
                margin-top: 4px;
                margin-bottom: 6px;
                box-shadow: 0 1px 4px alpha(black, 0.08);
            }
            .transfer-card:hover {
                border-color: alpha(@accent_color, 0.35);
            }
            progressbar.transfer-progress-bar {
                min-height: 10px;
                border-radius: 6px;
                margin-top: 4px;
                margin-bottom: 4px;
            }
            progressbar.transfer-progress-bar trough {
                min-height: 10px;
                border-radius: 6px;
                background-color: alpha(@card_fg_color, 0.1);
            }
            progressbar.transfer-progress-bar progress {
                min-height: 10px;
                border-radius: 6px;
                background-color: @accent_bg_color;
                background-image: linear-gradient(90deg, @accent_bg_color, #3584e4);
            }
            .badge-pill {
                border-radius: 12px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            .badge-pill.transferring {
                background-color: alpha(@accent_bg_color, 0.18);
                color: @accent_color;
            }
            .badge-pill.success {
                background-color: alpha(#2ec27e, 0.2);
                color: #2ec27e;
            }
            .badge-pill.error {
                background-color: alpha(#e01b24, 0.2);
                color: #e01b24;
            }
            .speed-tag {
                font-family: monospace;
                font-weight: 700;
                font-size: 12px;
                color: @accent_color;
            }
            .pct-tag {
                font-family: monospace;
                font-weight: 700;
                font-size: 12px;
            }
            .cancel-btn {
                border-radius: 8px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
                color: #e01b24;
                background-color: alpha(#e01b24, 0.12);
                border: 1px solid alpha(#e01b24, 0.25);
                transition: all 150ms ease;
            }
            .cancel-btn:hover {
                background-color: alpha(#e01b24, 0.24);
                border-color: alpha(#e01b24, 0.45);
            }
            .pin-display-badge {
                font-family: monospace;
                font-size: 26px;
                font-weight: 800;
                letter-spacing: 6px;
                padding: 10px 22px;
                border-radius: 10px;
                background: alpha(@accent_bg_color, 0.15);
                color: @accent_color;
                border: 1.5px solid alpha(@accent_color, 0.35);
            }
            "#,
        );
        if let Some(display) = gtk4::gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &css_provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }

        // Connect Add Files button in Send View
        let window_weak = window.downgrade();
        let send_view_clone = send_view.clone();
        send_view.add_files_btn.connect_clicked(move |_| {
            if let Some(parent) = window_weak.upgrade() {
                let file_chooser = gtk::FileChooserNative::new(
                    Some("Select Files to Share"),
                    Some(&parent),
                    gtk::FileChooserAction::Open,
                    Some("Select"),
                    Some("Cancel"),
                );
                file_chooser.set_select_multiple(true);

                let send_ref = send_view_clone.clone();
                file_chooser.connect_response(move |dialog, response| {
                    if response == gtk::ResponseType::Accept {
                        let files = dialog.files();
                        let mut paths = Vec::new();
                        for i in 0..files.n_items() {
                            if let Some(item) = files.item(i) {
                                if let Ok(file) = item.downcast::<gtk::gio::File>() {
                                    if let Some(path) = file.path() {
                                        paths.push(path);
                                    }
                                }
                            }
                        }
                        send_ref.stage_files(paths);
                    }
                });
                file_chooser.show();
            }
        });

        // Connect Clear Files button
        let send_view_clone2 = send_view.clone();
        send_view.clear_files_btn.connect_clicked(move |_| {
            send_view_clone2.clear_staged();
        });

        // Connect "Scan Nearby" button in Send View
        let send_view_clone_for_scan = send_view.clone();
        let overlay_clone_for_scan = toast_overlay.clone();
        send_view.refresh_btn.connect_clicked(move |_| {
            overlay_clone_for_scan.add_toast(adw::Toast::new("Scanning local network and Bluetooth for Quick Share targets..."));
            let neighbors = crate::ble::get_arp_neighbors();
            let my_ip = crate::discovery::get_local_ip();
            let sv = send_view_clone_for_scan.clone();
            for ip in neighbors {
                if Some(ip) == my_ip || ip.is_loopback() {
                    continue;
                }
                if let Some(port) = crate::ble::probe_quickshare_port(ip) {
                    sv.add_peer(DiscoveredPeer {
                        id: format!("lan_{}_{}", ip.to_string().replace('.', "_"), port),
                        name: format!("Quick Share Device ({})", ip),
                        device_type: DeviceType::Phone,
                        ip,
                        port,
                    });
                }
            }
        });

        // Connect "Add IP Address" button in Send View
        let window_weak2 = window.downgrade();
        let send_view_clone3 = send_view.clone();
        let overlay_clone2 = toast_overlay.clone();
        send_view.manual_ip_btn.connect_clicked(move |_| {
            if let Some(parent) = window_weak2.upgrade() {
                show_add_ip_dialog(&parent, send_view_clone3.clone(), overlay_clone2.clone());
            }
        });

        // Connect "Change Folder" button in Settings View
        let window_weak3 = window.downgrade();
        let settings_view_clone = settings_view.clone();
        let overlay_clone3 = toast_overlay.clone();
        settings_view.change_folder_btn.connect_clicked(move |_| {
            if let Some(parent) = window_weak3.upgrade() {
                let folder_chooser = gtk::FileChooserNative::new(
                    Some("Choose Downloads Destination"),
                    Some(&parent),
                    gtk::FileChooserAction::SelectFolder,
                    Some("Choose"),
                    Some("Cancel"),
                );

                let s_ref = settings_view_clone.clone();
                let o_ref = overlay_clone3.clone();
                folder_chooser.connect_response(move |dialog, response| {
                    if response == gtk::ResponseType::Accept {
                        if let Some(file) = dialog.file() {
                            if let Some(path) = file.path() {
                                s_ref.set_download_path(path.clone());
                                o_ref.add_toast(adw::Toast::new(&format!(
                                    "Download folder set to: {}",
                                    path.display()
                                )));
                            }
                        }
                    }
                });
                folder_chooser.show();
            }
        });

        // Connect "Send Files" shortcut from Receive View to switch to Send tab
        let view_stack_clone = view_stack.clone();
        let send_view_clone_for_rec = send_view.clone();
        receive_view.on_send_to_peer(move |peer| {
            send_view_clone_for_rec.add_peer(peer);
            view_stack_clone.set_visible_child_name("send");
        });

        // Connect Settings on_save feedback toast
        let overlay_clone4 = toast_overlay.clone();
        settings_view.on_save(move |_cfg| {
            overlay_clone4.add_toast(adw::Toast::new(&format!(
                "Settings saved to {}",
                crate::config::AppConfig::config_file_path().display()
            )));
        });

        // Connect cancel transfer feedback toasts
        let overlay_clone_rec_cancel = toast_overlay.clone();
        receive_view.on_cancel_transfer(move |_id| {
            overlay_clone_rec_cancel.add_toast(adw::Toast::new("Transfer cancelled."));
        });

        let overlay_clone_send_cancel = toast_overlay.clone();
        send_view.on_cancel_transfer(move |_id| {
            overlay_clone_send_cancel.add_toast(adw::Toast::new("Transfer cancelled."));
        });

        Self {
            window,
            toast_overlay,
            receive_view,
            send_view,
            settings_view,
        }
    }

    pub fn handle_event(&self, event: AppEvent) {
        match event {
            AppEvent::PeerDiscovered(peer) => {
                let name = peer.name.clone();
                self.send_view.add_peer(peer.clone());
                self.receive_view.add_peer(peer);
                self.toast_overlay.add_toast(adw::Toast::new(&format!(
                    "Discovered nearby peer: {}",
                    name
                )));
            }
            AppEvent::PeerLost(id) => {
                self.send_view.mark_peer_lost(&id);
                self.receive_view.mark_peer_lost(&id);
            }
            AppEvent::IncomingTransferRequest {
                session_id: _,
                peer_name,
                files,
                total_size,
                pin,
                accept_tx,
            } => {
                self.show_incoming_transfer_dialog(peer_name, files, total_size, pin, accept_tx);
            }
            AppEvent::TransferStarted {
                transfer_id,
                filename,
                total,
                is_send,
            } => {
                if is_send {
                    self.send_view.on_transfer_started(transfer_id, &filename, total);
                } else {
                    self.receive_view.on_transfer_started(transfer_id, &filename, total, is_send);
                }
                let verb = if is_send { "Sending" } else { "Receiving" };
                self.toast_overlay.add_toast(adw::Toast::new(&format!("{} {}", verb, filename)));
            }
            AppEvent::TransferProgress {
                transfer_id,
                filename: _,
                transferred,
                total,
                speed_mbps,
                is_send,
            } => {
                if is_send {
                    self.send_view.on_transfer_progress(transfer_id, transferred, total, speed_mbps);
                } else {
                    self.receive_view.on_transfer_progress(transfer_id, transferred, total, speed_mbps);
                }
            }
            AppEvent::TransferCompleted {
                transfer_id,
                filename,
                file_path,
                is_send,
            } => {
                if is_send {
                    self.send_view.on_transfer_completed(transfer_id, file_path);
                } else {
                    self.receive_view.on_transfer_completed(transfer_id, file_path);
                }
                let msg = if is_send {
                    format!("Successfully sent '{}'", filename)
                } else {
                    format!("Saved '{}' to Downloads", filename)
                };
                self.toast_overlay.add_toast(adw::Toast::new(&msg));
            }
            AppEvent::TransferFailed {
                transfer_id,
                filename,
                error,
            } => {
                self.send_view.on_transfer_failed(transfer_id, &error);
                self.receive_view.on_transfer_failed(transfer_id, &error);
                self.toast_overlay.add_toast(adw::Toast::new(&format!(
                    "Transfer failed for '{}': {}",
                    filename, error
                )));
            }
            AppEvent::StatusNotification(msg) => {
                self.toast_overlay.add_toast(adw::Toast::new(&msg));
            }
        }
    }

    fn show_incoming_transfer_dialog(
        &self,
        peer_name: String,
        files: Vec<(String, u64)>,
        total_size: u64,
        pin: String,
        accept_tx: oneshot::Sender<bool>,
    ) {
        let heading = format!("Incoming Transfer from {}", peer_name);

        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(&heading),
            None,
        );

        let content_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
        content_box.set_margin_start(16);
        content_box.set_margin_end(16);
        content_box.set_margin_top(8);
        content_box.set_margin_bottom(8);

        // 1. Files List Card
        let files_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        files_card.add_css_class("card");
        files_card.set_margin_top(2);
        files_card.set_margin_bottom(6);

        for (name, size) in files.iter().take(3) {
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
            row.set_margin_start(12);
            row.set_margin_end(12);
            row.set_margin_top(8);
            row.set_margin_bottom(6);

            let icon_name = crate::ui::transfer_card::get_icon_for_filename(name);
            let icon = gtk::Image::from_icon_name(icon_name);
            icon.set_icon_size(gtk::IconSize::Large);

            let name_label = gtk::Label::new(Some(name));
            name_label.set_halign(gtk::Align::Start);
            name_label.set_hexpand(true);
            name_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
            name_label.set_max_width_chars(28);
            name_label.add_css_class("heading");

            let size_label = gtk::Label::new(Some(&crate::ui::transfer_card::format_size(*size)));
            size_label.add_css_class("dim-label");

            row.append(&icon);
            row.append(&name_label);
            row.append(&size_label);
            files_card.append(&row);
        }

        if files.len() > 3 {
            let more_label = gtk::Label::new(Some(&format!("...and {} more files", files.len() - 3)));
            more_label.add_css_class("dim-label");
            more_label.set_margin_bottom(6);
            files_card.append(&more_label);
        }

        // Summary row: Total size
        let total_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        total_row.set_margin_start(12);
        total_row.set_margin_end(12);
        total_row.set_margin_bottom(8);

        let total_title = gtk::Label::new(Some("Total Size:"));
        total_title.set_halign(gtk::Align::Start);
        total_title.set_hexpand(true);
        total_title.add_css_class("dim-label");

        let total_val = gtk::Label::new(Some(&crate::ui::transfer_card::format_size(total_size)));
        total_val.add_css_class("heading");

        total_row.append(&total_title);
        total_row.append(&total_val);
        files_card.append(&total_row);

        content_box.append(&files_card);

        // 2. PIN Verification Card
        let pin_card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        pin_card.add_css_class("card");
        pin_card.set_margin_top(4);
        pin_card.set_margin_bottom(4);
        pin_card.set_halign(gtk::Align::Center);

        let pin_header = gtk::Label::new(Some("MUTUAL VERIFICATION PIN"));
        pin_header.add_css_class("caption");
        pin_header.add_css_class("dim-label");
        pin_header.set_margin_top(10);

        let pin_label = gtk::Label::new(Some(&format!("🔐  {}  ", pin)));
        pin_label.add_css_class("pin-display-badge");
        pin_label.set_margin_bottom(4);

        let pin_hint = gtk::Label::new(Some("Confirm that this 4-digit code matches the sender's screen before accepting"));
        pin_hint.add_css_class("caption");
        pin_hint.add_css_class("dim-label");
        pin_hint.set_margin_bottom(10);
        pin_hint.set_margin_start(16);
        pin_hint.set_margin_end(16);

        pin_card.append(&pin_header);
        pin_card.append(&pin_label);
        pin_card.append(&pin_hint);

        content_box.append(&pin_card);

        dialog.set_extra_child(Some(&content_box));
        dialog.add_response("decline", "Decline");
        dialog.add_response("accept", "Accept");
        dialog.set_response_appearance("accept", adw::ResponseAppearance::Suggested);
        dialog.set_response_appearance("decline", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("accept"));
        dialog.set_close_response("decline");

        let tx_cell = Rc::new(RefCell::new(Some(accept_tx)));
        dialog.connect_response(None, move |_, response| {
            if let Some(tx) = tx_cell.borrow_mut().take() {
                let accepted = response == "accept";
                let _ = tx.send(accepted);
            }
        });

        dialog.present();
    }
}

fn show_add_ip_dialog(
    parent: &adw::ApplicationWindow,
    send_view: Rc<SendView>,
    overlay: adw::ToastOverlay,
) {
    let dialog = adw::MessageDialog::new(
        Some(parent),
        Some("Add Device by IP Address"),
        Some("Enter the target IP address and optional port (e.g. 192.168.1.7:8765):"),
    );

    let list_box = gtk::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_margin_start(16);
    list_box.set_margin_end(16);
    list_box.set_margin_top(8);
    list_box.set_margin_bottom(8);

    let entry = adw::EntryRow::builder()
        .title("IP:Port")
        .text("192.168.1.7:8765")
        .build();
    list_box.append(&entry);

    dialog.set_extra_child(Some(&list_box));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("add", "Add Device");
    dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("add"));

    let entry_clone = entry.clone();
    dialog.connect_response(None, move |_, response| {
        if response == "add" {
            let input = entry_clone.text().to_string();
            let trimmed = input.trim();
            let (ip_str, explicit_port) = if let Some((h, p)) = trimmed.split_once(':') {
                (h, p.parse::<u16>().ok())
            } else {
                (trimmed, None)
            };

            match ip_str.parse::<IpAddr>() {
                Ok(ip) => {
                    let port = detect_or_default_port(ip, explicit_port);
                    let peer = DiscoveredPeer {
                        id: format!("ip_{}", ip_str.replace('.', "_")),
                        name: format!("Quick Share Device ({})", ip_str),
                        device_type: DeviceType::Phone,
                        ip,
                        port,
                    };
                    let name = peer.name.clone();
                    send_view.add_peer(peer);
                    overlay.add_toast(adw::Toast::new(&format!("Target added: {} (port {})", name, port)));
                }
                Err(e) => {
                    overlay.add_toast(adw::Toast::new(&format!("Invalid IP address: {}", e)));
                }
            }
        }
    });

    dialog.present();
}

fn detect_or_default_port(ip: IpAddr, explicit_port: Option<u16>) -> u16 {
    if let Some(p) = explicit_port {
        return p;
    }
    for port in [53601, 53317, 8765] {
        let addr = std::net::SocketAddr::new(ip, port);
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(150)) {
            drop(stream);
            return port;
        }
    }
    53601
}
