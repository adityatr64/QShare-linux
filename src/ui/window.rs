use crate::events::{AppEvent, DeviceType, DiscoveredPeer};
use crate::qr::QrConnectionInfo;
use crate::ui::receive_view::ReceiveView;
use crate::ui::send_view::SendView;
use crate::ui::settings_view::SettingsView;
use gtk4::gdk;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use tokio::sync::oneshot;

pub struct MainWindow {
    pub window: adw::ApplicationWindow,
    pub toast_overlay: adw::ToastOverlay,
    pub receive_view: Rc<ReceiveView>,
    pub send_view: Rc<SendView>,
    pub settings_view: Rc<SettingsView>,
    pub qr_info: Rc<RefCell<QrConnectionInfo>>,
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
        let receive_view = Rc::new(ReceiveView::new());
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

        let ip_parsed = local_ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        let qr_info = Rc::new(RefCell::new(QrConnectionInfo {
            ip: ip_parsed,
            port,
            endpoint_id: endpoint_id.to_string(),
            device_name: device_name.to_string(),
        }));

        receive_view.set_qr_info(&qr_info.borrow());

        // Connect Copy Link button
        let qr_info_clone = qr_info.clone();
        let overlay_clone = toast_overlay.clone();
        receive_view.copy_link_btn.connect_clicked(move |_| {
            let uri = qr_info_clone.borrow().to_uri();
            if let Some(display) = gdk::Display::default() {
                display.clipboard().set_text(&uri);
                overlay_clone.add_toast(adw::Toast::new("Direct pairing link copied to clipboard!"));
            }
        });

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

        // Connect "Connect via QR / Direct IP" button in Send View
        let window_weak2 = window.downgrade();
        let send_view_clone3 = send_view.clone();
        let overlay_clone2 = toast_overlay.clone();
        send_view.qr_connect_btn.connect_clicked(move |_| {
            if let Some(parent) = window_weak2.upgrade() {
                show_qr_connect_dialog(&parent, send_view_clone3.clone(), overlay_clone2.clone());
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

        Self {
            window,
            toast_overlay,
            receive_view,
            send_view,
            settings_view,
            qr_info,
        }
    }

    pub fn handle_event(&self, event: AppEvent) {
        match event {
            AppEvent::PeerDiscovered(peer) => {
                let name = peer.name.clone();
                self.send_view.add_peer(peer);
                self.toast_overlay.add_toast(adw::Toast::new(&format!(
                    "Discovered nearby peer: {}",
                    name
                )));
            }
            AppEvent::PeerLost(id) => {
                self.send_view.remove_peer(&id);
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
                self.receive_view.on_transfer_started(transfer_id, &filename, total, is_send);
                let verb = if is_send { "Sending" } else { "Receiving" };
                self.toast_overlay.add_toast(adw::Toast::new(&format!("{} {}", verb, filename)));
            }
            AppEvent::TransferProgress {
                transfer_id,
                filename: _,
                transferred,
                total,
                speed_mbps,
                is_send: _,
            } => {
                self.receive_view.on_transfer_progress(transfer_id, transferred, total, speed_mbps);
            }
            AppEvent::TransferCompleted {
                transfer_id,
                filename,
                is_send,
            } => {
                self.receive_view.on_transfer_completed(transfer_id);
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
        let total_mb = total_size as f64 / 1_048_576.0;
        let file_summary = if files.len() == 1 {
            format!("File: {}", files[0].0)
        } else {
            let names: Vec<String> = files.iter().take(3).map(|(f, _)| f.clone()).collect();
            let more = if files.len() > 3 {
                format!(" and {} more", files.len() - 3)
            } else {
                String::new()
            };
            format!("Files: {}{}", names.join(", "), more)
        };

        let heading = format!("Incoming Transfer from '{}'", peer_name);
        let body = format!(
            "{}\nTotal Size: {:.2} MB\n\n═══════════════════════════════════════\n  🔐 MUTUAL VERIFICATION PIN: [ {} ]\n═══════════════════════════════════════\n\nConfirm that this 4-digit code matches the sender device screen before accepting.",
            file_summary, total_mb, pin
        );

        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(&heading),
            Some(&body),
        );

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

fn show_qr_connect_dialog(
    parent: &adw::ApplicationWindow,
    send_view: Rc<SendView>,
    overlay: adw::ToastOverlay,
) {
    let dialog = adw::MessageDialog::new(
        Some(parent),
        Some("Connect via QR or Direct Connection"),
        Some("Enter a quickshare:// URL, JSON payload, or IP:Port (e.g. 192.168.1.100:8765)"),
    );

    let entry = adw::EntryRow::builder()
        .title("Direct Connection Address")
        .text("quickshare://")
        .build();
    entry.set_margin_start(16);
    entry.set_margin_end(16);
    entry.set_margin_top(8);
    entry.set_margin_bottom(8);

    dialog.set_extra_child(Some(&entry));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("connect", "Connect and Add Target");
    dialog.set_response_appearance("connect", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("connect"));

    let entry_clone = entry.clone();
    dialog.connect_response(None, move |_, response| {
        if response == "connect" {
            let input = entry_clone.text().to_string();
            match QrConnectionInfo::parse(&input) {
                Ok(info) => {
                    let peer = DiscoveredPeer {
                        id: info.endpoint_id,
                        name: info.device_name,
                        device_type: DeviceType::Phone,
                        ip: info.ip,
                        port: info.port,
                    };
                    let name = peer.name.clone();
                    send_view.add_peer(peer);
                    overlay.add_toast(adw::Toast::new(&format!("Direct peer added: {}", name)));
                }
                Err(e) => {
                    overlay.add_toast(adw::Toast::new(&format!("Invalid QR connection format: {}", e)));
                }
            }
        }
    });

    dialog.present();
}
