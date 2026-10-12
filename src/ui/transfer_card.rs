use gtk4 as gtk;
use gtk4::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

pub fn get_icon_for_filename(filename: &str) -> &'static str {
    let lower = filename.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "svg" | "heic" | "avif" | "ico" => {
            "image-x-generic-symbolic"
        }
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "wmv" | "flv" | "3gp" | "m4v" => {
            "video-x-generic-symbolic"
        }
        "mp3" | "flac" | "wav" | "ogg" | "m4a" | "aac" | "opus" | "wma" => {
            "audio-x-generic-symbolic"
        }
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" | "zst" | "tgz" => {
            "package-x-generic-symbolic"
        }
        "pdf" => "x-office-document-symbolic",
        "doc" | "docx" | "odt" | "rtf" => "x-office-document-symbolic",
        "xls" | "xlsx" | "ods" | "csv" => "x-office-spreadsheet-symbolic",
        "ppt" | "pptx" | "odp" => "x-office-presentation-symbolic",
        "txt" | "md" | "json" | "xml" | "yaml" | "yml" | "rs" | "py" | "c" | "cpp" | "h"
        | "js" | "ts" | "html" | "css" | "sh" => "text-x-generic-symbolic",
        "apk" | "deb" | "rpm" | "appimage" => "application-x-executable-symbolic",
        _ => "text-x-generic-symbolic",
    }
}

#[derive(Clone)]
pub struct TransferCard {
    pub container: gtk::Box,
    pub title_label: gtk::Label,
    pub status_badge: gtk::Label,
    pub cancel_btn: gtk::Button,
    pub progress_bar: gtk::ProgressBar,
    pub size_label: gtk::Label,
    pub speed_label: gtk::Label,
    pub eta_label: gtk::Label,
    pub pct_label: gtk::Label,
    pub actions_box: gtk::Box,
    pub open_file_btn: gtk::Button,
    pub open_folder_btn: gtk::Button,
    pub dismiss_btn: gtk::Button,
    pub cancel_callbacks: Rc<RefCell<Vec<Box<dyn Fn() + 'static>>>>,
    pub is_send: bool,
    pub total_bytes: u64,
}

impl TransferCard {
    pub fn new(filename: &str, total_bytes: u64, is_send: bool) -> Self {
        let container = gtk::Box::new(gtk::Orientation::Vertical, 8);
        container.add_css_class("card");
        container.add_css_class("transfer-card");
        container.set_margin_start(4);
        container.set_margin_end(4);
        container.set_margin_top(4);
        container.set_margin_bottom(6);

        // Header line: icon + filename + direction subtitle + pill status badge + cancel button
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        header.set_valign(gtk::Align::Center);

        let icon_name = get_icon_for_filename(filename);
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.set_icon_size(gtk::IconSize::Large);

        let title_box = gtk::Box::new(gtk::Orientation::Vertical, 2);
        title_box.set_hexpand(true);
        title_box.set_halign(gtk::Align::Start);

        let title_label = gtk::Label::new(Some(filename));
        title_label.set_halign(gtk::Align::Start);
        title_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        title_label.set_max_width_chars(32);
        title_label.add_css_class("heading");

        let subtitle_text = if is_send {
            format!("Sending • {}", format_size(total_bytes))
        } else {
            format!("Receiving • {}", format_size(total_bytes))
        };
        let subtitle_label = gtk::Label::new(Some(&subtitle_text));
        subtitle_label.set_halign(gtk::Align::Start);
        subtitle_label.add_css_class("caption");
        subtitle_label.add_css_class("dim-label");

        title_box.append(&title_label);
        title_box.append(&subtitle_label);

        let status_badge = gtk::Label::new(Some(if is_send { "Sending (0%)" } else { "Receiving (0%)" }));
        status_badge.add_css_class("badge-pill");
        status_badge.add_css_class("transferring");
        status_badge.set_valign(gtk::Align::Center);

        let cancel_btn = gtk::Button::builder()
            .label("Cancel")
            .icon_name("process-stop-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text("Cancel this transfer")
            .build();
        cancel_btn.add_css_class("cancel-btn");

        header.append(&icon);
        header.append(&title_box);
        header.append(&status_badge);
        header.append(&cancel_btn);

        // Progress bar
        let progress_bar = gtk::ProgressBar::new();
        progress_bar.set_fraction(0.0);
        progress_bar.set_hexpand(true);
        progress_bar.add_css_class("transfer-progress-bar");

        // Stats bar (Size, Speed, ETA, Percentage)
        let stats_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        stats_box.set_valign(gtk::Align::Center);

        let size_label = gtk::Label::new(Some(&format!(
            "0 B / {}",
            format_size(total_bytes)
        )));
        size_label.set_halign(gtk::Align::Start);
        size_label.add_css_class("caption");
        size_label.add_css_class("dim-label");
        size_label.set_hexpand(true);

        let speed_label = gtk::Label::new(Some("⚡ 0.0 MB/s"));
        speed_label.add_css_class("speed-tag");

        let eta_label = gtk::Label::new(Some("ETA: --"));
        eta_label.add_css_class("caption");
        eta_label.add_css_class("dim-label");

        let pct_label = gtk::Label::new(Some("0%"));
        pct_label.add_css_class("pct-tag");

        stats_box.append(&size_label);
        stats_box.append(&speed_label);
        stats_box.append(&eta_label);
        stats_box.append(&pct_label);

        // Actions row (Revealed when completed or cancelled)
        let actions_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions_box.set_halign(gtk::Align::End);
        actions_box.set_visible(false);

        let open_file_btn = gtk::Button::builder()
            .label("Open File")
            .icon_name("document-open-symbolic")
            .build();
        open_file_btn.add_css_class("suggested-action");

        let open_folder_btn = gtk::Button::builder()
            .label("Show in Folder")
            .icon_name("folder-symbolic")
            .build();
        open_folder_btn.add_css_class("flat");

        let dismiss_btn = gtk::Button::builder()
            .icon_name("window-close-symbolic")
            .tooltip_text("Dismiss")
            .build();
        dismiss_btn.add_css_class("flat");

        actions_box.append(&open_file_btn);
        actions_box.append(&open_folder_btn);
        actions_box.append(&dismiss_btn);

        // Connect dismiss button to remove card from parent container
        let container_weak = container.downgrade();
        dismiss_btn.connect_clicked(move |_| {
            if let Some(c) = container_weak.upgrade() {
                if let Some(parent) = c.parent() {
                    if let Ok(p_box) = parent.downcast::<gtk::Box>() {
                        p_box.remove(&c);
                    }
                }
            }
        });

        // Cancel callback registry
        let cancel_callbacks: Rc<RefCell<Vec<Box<dyn Fn() + 'static>>>> = Rc::new(RefCell::new(Vec::new()));
        let cbs_clone = cancel_callbacks.clone();
        let cancel_btn_clone = cancel_btn.clone();
        let status_clone = status_badge.clone();
        let size_clone = size_label.clone();
        let speed_clone = speed_label.clone();
        let eta_clone = eta_label.clone();
        let pct_clone = pct_label.clone();
        let actions_clone = actions_box.clone();
        let open_file_clone = open_file_btn.clone();
        let open_folder_clone = open_folder_btn.clone();

        cancel_btn.connect_clicked(move |_| {
            cancel_btn_clone.set_visible(false);
            status_clone.set_text("Cancelled");
            status_clone.remove_css_class("transferring");
            status_clone.remove_css_class("success");
            status_clone.add_css_class("error");
            size_clone.set_text("Transfer cancelled by user");
            speed_clone.set_text("Cancelled");
            eta_clone.set_text("");
            pct_clone.set_text("");

            open_file_clone.set_visible(false);
            open_folder_clone.set_visible(false);
            actions_clone.set_visible(true);

            for cb in cbs_clone.borrow().iter() {
                cb();
            }
        });

        container.append(&header);
        container.append(&progress_bar);
        container.append(&stats_box);
        container.append(&actions_box);

        Self {
            container,
            title_label,
            status_badge,
            cancel_btn,
            progress_bar,
            size_label,
            speed_label,
            eta_label,
            pct_label,
            actions_box,
            open_file_btn,
            open_folder_btn,
            dismiss_btn,
            cancel_callbacks,
            is_send,
            total_bytes,
        }
    }

    pub fn on_cancel(&self, callback: impl Fn() + 'static) {
        self.cancel_callbacks.borrow_mut().push(Box::new(callback));
    }

    pub fn cancel(&self) {
        self.cancel_btn.set_visible(false);
        self.status_badge.set_text("Cancelled");
        self.status_badge.remove_css_class("transferring");
        self.status_badge.remove_css_class("success");
        self.status_badge.add_css_class("error");
        self.size_label.set_text("Transfer cancelled by user");
        self.speed_label.set_text("Cancelled");
        self.eta_label.set_text("");
        self.pct_label.set_text("");

        self.open_file_btn.set_visible(false);
        self.open_folder_btn.set_visible(false);
        self.actions_box.set_visible(true);
    }

    pub fn update(&self, transferred: u64, total: u64, speed_mbps: f64) {
        let fraction = if total > 0 {
            (transferred as f64 / total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.progress_bar.set_fraction(fraction);

        let pct = (fraction * 100.0) as u32;
        let action = if self.is_send { "Sending" } else { "Receiving" };
        self.status_badge.set_text(&format!("{} ({}%)", action, pct));

        self.size_label.set_text(&format!(
            "{} / {}",
            format_size(transferred),
            format_size(total)
        ));

        self.speed_label.set_text(&format!("⚡ {:.1} MB/s", speed_mbps));

        if speed_mbps > 0.05 && total > transferred {
            let remaining_bytes = total - transferred;
            let secs = (remaining_bytes as f64) / (speed_mbps * 1_048_576.0);
            if secs < 60.0 {
                self.eta_label.set_text(&format!("ETA ~{}s", secs.ceil() as u64));
            } else {
                self.eta_label.set_text(&format!(
                    "ETA ~{}m {}s",
                    (secs / 60.0) as u64,
                    (secs % 60.0).ceil() as u64
                ));
            }
        } else if fraction >= 1.0 {
            self.eta_label.set_text("Done");
        } else {
            self.eta_label.set_text("ETA: --");
        }

        self.pct_label.set_text(&format!("{}%", pct));
    }

    pub fn complete(&self, file_path: Option<PathBuf>) {
        self.cancel_btn.set_visible(false);
        self.progress_bar.set_fraction(1.0);
        self.status_badge.set_text("Completed ✓");
        self.status_badge.remove_css_class("transferring");
        self.status_badge.add_css_class("success");

        let action = if self.is_send { "Sent" } else { "Received" };
        self.size_label.set_text(&format!(
            "Successfully {} • {}",
            action,
            format_size(self.total_bytes)
        ));
        self.speed_label.set_text("✓ Complete");
        self.eta_label.set_text("");
        self.pct_label.set_text("100%");

        self.actions_box.set_visible(true);

        if let Some(path) = file_path {
            let p1 = path.clone();
            self.open_file_btn.connect_clicked(move |_| {
                let _ = std::process::Command::new("xdg-open")
                    .arg(&p1)
                    .spawn();
            });

            let p2 = path;
            self.open_folder_btn.connect_clicked(move |_| {
                let folder = if p2.is_dir() {
                    p2.clone()
                } else {
                    p2.parent().unwrap_or(&p2).to_path_buf()
                };
                let _ = std::process::Command::new("xdg-open")
                    .arg(&folder)
                    .spawn();
            });
        } else {
            self.open_file_btn.set_visible(false);
            self.open_folder_btn.set_visible(false);
        }
    }

    pub fn fail(&self, err: &str) {
        self.cancel_btn.set_visible(false);
        self.status_badge.set_text("Failed ✗");
        self.status_badge.remove_css_class("transferring");
        self.status_badge.add_css_class("error");
        self.size_label.set_text(&format!("Error: {}", err));
        self.speed_label.set_text("Failed");
        self.eta_label.set_text("");
        self.pct_label.set_text("");

        self.open_file_btn.set_visible(false);
        self.open_folder_btn.set_visible(false);
        self.actions_box.set_visible(true);
    }
}
