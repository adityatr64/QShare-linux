use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

#[derive(Clone)]
pub struct TransferCard {
    pub container: gtk::Box,
    pub title_label: gtk::Label,
    pub status_badge: gtk::Label,
    pub progress_bar: gtk::ProgressBar,
    pub stats_label: gtk::Label,
}

impl TransferCard {
    pub fn new(filename: &str, total_bytes: u64, is_send: bool) -> Self {
        let container = gtk::Box::new(gtk::Orientation::Vertical, 6);
        container.add_css_class("card");
        container.set_margin_start(12);
        container.set_margin_end(12);
        container.set_margin_top(6);
        container.set_margin_bottom(6);

        // Header line: icon + filename + direction badge
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let icon_name = if is_send { "mail-send-symbolic" } else { "folder-download-symbolic" };
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.set_icon_size(gtk::IconSize::Large);

        let title_label = gtk::Label::new(Some(filename));
        title_label.set_halign(gtk::Align::Start);
        title_label.set_hexpand(true);
        title_label.add_css_class("heading");

        let status_text = if is_send { "Sending..." } else { "Receiving..." };
        let status_badge = gtk::Label::new(Some(status_text));
        status_badge.add_css_class("accent");

        header.append(&icon);
        header.append(&title_label);
        header.append(&status_badge);

        // Progress bar
        let progress_bar = gtk::ProgressBar::new();
        progress_bar.set_fraction(0.0);
        progress_bar.set_hexpand(true);

        // Stats line: bytes & speed
        let total_mb = total_bytes as f64 / 1_048_576.0;
        let stats_label = gtk::Label::new(Some(&format!("0.00 / {:.2} MB (0.0 MB/s)", total_mb)));
        stats_label.set_halign(gtk::Align::Start);
        stats_label.add_css_class("caption");

        container.append(&header);
        container.append(&progress_bar);
        container.append(&stats_label);

        Self {
            container,
            title_label,
            status_badge,
            progress_bar,
            stats_label,
        }
    }

    pub fn update(&self, transferred: u64, total: u64, speed_mbps: f64) {
        let fraction = if total > 0 {
            (transferred as f64 / total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.progress_bar.set_fraction(fraction);

        let trans_mb = transferred as f64 / 1_048_576.0;
        let total_mb = total as f64 / 1_048_576.0;
        self.stats_label.set_text(&format!(
            "{:.2} / {:.2} MB ({:.1} MB/s) — {:.0}%",
            trans_mb,
            total_mb,
            speed_mbps,
            fraction * 100.0
        ));
    }

    pub fn complete(&self) {
        self.progress_bar.set_fraction(1.0);
        self.status_badge.set_text("Completed ✓");
        self.status_badge.remove_css_class("accent");
        self.status_badge.add_css_class("success");
        self.stats_label.set_text("Transfer completed successfully");
    }

    pub fn fail(&self, err: &str) {
        self.status_badge.set_text("Failed ✗");
        self.status_badge.remove_css_class("accent");
        self.status_badge.add_css_class("error");
        self.stats_label.set_text(&format!("Error: {}", err));
    }
}

pub struct ReceiveView {
    pub page: adw::PreferencesPage,
    pub visibility_switch: adw::SwitchRow,
    pub empty_placeholder: adw::StatusPage,
    pub transfers_box: gtk::Box,
    pub active_transfers: Rc<RefCell<HashMap<u64, TransferCard>>>,
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

        let ep_row = adw::ActionRow::builder()
            .title("Endpoint ID & Listening Address")
            .subtitle(&format!("ID: {} | {}:{}", endpoint_id, local_ip, port))
            .build();
        let ep_icon = gtk::Image::from_icon_name("network-wireless-symbolic");
        ep_row.add_prefix(&ep_icon);
        vis_group.add(&ep_row);

        page.add(&vis_group);

        // 2. Active / Recent Transfers Area
        let trans_group = adw::PreferencesGroup::new();
        trans_group.set_title("Transfers");

        let transfers_box = gtk::Box::new(gtk::Orientation::Vertical, 6);

        let empty_placeholder = adw::StatusPage::builder()
            .title("Ready to Receive")
            .description("Open Quick Share or Nearby Share on your mobile device to transfer files directly to this PC")
            .icon_name("folder-download-symbolic")
            .build();
        empty_placeholder.set_height_request(180);

        trans_group.add(&empty_placeholder);
        trans_group.add(&transfers_box);
        page.add(&trans_group);

        Self {
            page,
            visibility_switch,
            empty_placeholder,
            transfers_box,
            active_transfers: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    pub fn on_transfer_started(&self, id: u64, filename: &str, total: u64, is_send: bool) {
        self.empty_placeholder.set_visible(false);
        let card = TransferCard::new(filename, total, is_send);
        self.transfers_box.prepend(&card.container);
        self.active_transfers.borrow_mut().insert(id, card);
    }

    pub fn on_transfer_progress(&self, id: u64, transferred: u64, total: u64, speed_mbps: f64) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.update(transferred, total, speed_mbps);
        }
    }

    pub fn on_transfer_completed(&self, id: u64) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.complete();
        }
    }

    pub fn on_transfer_failed(&self, id: u64, err: &str) {
        if let Some(card) = self.active_transfers.borrow().get(&id) {
            card.fail(err);
        }
    }
}
