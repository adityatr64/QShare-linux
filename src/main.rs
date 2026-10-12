mod ble;
mod config;
mod crypto;
mod discovery;
mod events;
mod proto;
mod secure_frame;
mod sender;
mod session;
mod transport;
mod ukey2;
pub mod ui;

use anyhow::{Context, Result};
use ble::{BleAdvertiser, BleScanner};
use clap::Parser;
use config::AppConfig;
use discovery::{get_local_ip, MdnsAdvertiser, MdnsBrowser};
use events::AppEvent;
use libadwaita as adw;
use libadwaita::prelude::*;
use sender::QuickShareSender;
use session::QuickShareSession;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use ui::window::MainWindow;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "QShare-linux",
    author = "Aditya <adityatr64>",
    version = "0.2.0",
    about = "Native Libadwaita desktop client and receiver daemon for Google Quick Share / Nearby Share"
)]
struct Args {
    /// TCP port to listen on for incoming transfers
    #[arg(short, long, default_value_t = 8765)]
    port: u16,

    /// Device display name advertised via mDNS and BLE to nearby senders
    #[arg(short, long, default_value = "Linux Quick Share")]
    name: String,

    /// Destination directory for received files
    #[arg(short, long)]
    download_dir: Option<PathBuf>,

    /// Run as headless daemon in terminal without GUI
    #[arg(long)]
    headless: bool,

    /// Direct target peer IP:Port to send files to (CLI mode)
    #[arg(long)]
    target: Option<String>,

    /// Files to send directly via CLI mode
    #[arg(long, num_args = 1..)]
    send: Option<Vec<PathBuf>>,

    /// Inspect local network interfaces, port bindings, and daemon status
    #[arg(long)]
    check_network: bool,

    /// Automatically configure firewall rules (ufw, firewalld, nftables)
    #[arg(long)]
    setup_firewall: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,qshare_linux=debug,QShare_linux=debug")),
        )
        .init();

    let args = Args::parse();

    if args.check_network {
        return run_network_check(args.port);
    }

    if args.setup_firewall {
        return run_firewall_setup();
    }

    // 1. Load persistent config from ~/.config/quickshare/settings.json
    let mut config = AppConfig::load();
    if args.name != "Linux Quick Share" {
        config.device_name = args.name.clone();
    }
    if args.port != 8765 {
        config.port = args.port;
    }
    if let Some(ref d) = args.download_dir {
        config.download_dir = d.clone();
    }
    let _ = config.save();

    let download_path = config.download_dir.clone();
    let _ = std::fs::create_dir_all(&download_path);

    // Initialize Tokio runtime in the background
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build Tokio multi-threaded runtime")?;

    if args.headless || args.send.is_some() {
        return rt.block_on(run_headless(args, download_path));
    }

    // Run native Libadwaita GUI application
    run_gui(args, config, rt)
}

fn run_network_check(port: u16) -> Result<()> {
    println!("==================================================");
    println!(" Quick Share Linux: Network Diagnostics");
    println!("==================================================");

    let ip = get_local_ip().map(|i| i.to_string()).unwrap_or_else(|| "127.0.0.1".to_string());
    println!("Local Subnet IP:          {}", ip);

    match std::net::TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(_) => println!("[OK] TCP Port {}:         Available and bindable", port),
        Err(e) => println!("[WARN] TCP Port {}:       Cannot bind ({})", port, e),
    }

    if let Ok(out) = std::process::Command::new("systemctl").args(["is-active", "avahi-daemon"]).output() {
        let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("Avahi (mDNS) daemon:      {}", status);
    } else {
        println!("Avahi (mDNS) daemon:      unknown (systemctl not available)");
    }

    if let Ok(out) = std::process::Command::new("systemctl").args(["is-active", "bluetooth"]).output() {
        let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("Bluetooth daemon:         {}", status);
    } else {
        println!("Bluetooth daemon:         unknown");
    }

    // Check UFW
    if let Ok(out) = std::process::Command::new("ufw").args(["status"]).output() {
        let status = String::from_utf8_lossy(&out.stdout);
        let active = status.lines().next().unwrap_or("unknown");
        println!("UFW Firewall status:      {}", active.trim());
    }

    println!("==================================================");
    Ok(())
}

fn run_firewall_setup() -> Result<()> {
    println!("==================================================");
    println!(" Quick Share Linux: Auto-configuring Firewall");
    println!("==================================================");

    let script_paths = [
        "./scripts/setup-firewall.sh",
        "/usr/local/share/quickshare/setup-firewall.sh",
    ];

    for p in script_paths {
        if std::path::Path::new(p).exists() {
            let status = std::process::Command::new("bash").arg(p).status()?;
            if status.success() {
                return Ok(());
            }
        }
    }

    if let Ok(out) = std::process::Command::new("ufw").args(["status"]).output() {
        if String::from_utf8_lossy(&out.stdout).contains("active") {
            println!("[INFO] Configuring UFW rules...");
            let _ = std::process::Command::new("sudo").args(["ufw", "allow", "5353/udp", "comment", "Quick Share mDNS"]).status();
            let _ = std::process::Command::new("sudo").args(["ufw", "allow", "8765:8815/tcp", "comment", "Quick Share TCP"]).status();
            let _ = std::process::Command::new("sudo").args(["ufw", "reload"]).status();
            println!("[SUCCESS] UFW rules configured.");
            return Ok(());
        }
    }

    println!("[INFO] Please run './scripts/setup-firewall.sh' with sudo privileges.");
    Ok(())
}

async fn bind_listener_with_fallback(preferred_port: u16) -> Result<(TcpListener, u16)> {
    match TcpListener::bind(format!("0.0.0.0:{}", preferred_port)).await {
        Ok(l) => Ok((l, preferred_port)),
        Err(e) => {
            warn!("Port {} unavailable ({:?}), trying next ports...", preferred_port, e);
            for p in (preferred_port + 1)..=(preferred_port + 50) {
                if let Ok(l) = TcpListener::bind(format!("0.0.0.0:{}", p)).await {
                    info!("Bound TCP listener on alternative port {}", p);
                    return Ok((l, p));
                }
            }
            Err(e.into())
        }
    }
}

fn run_gui(args: Args, config: AppConfig, rt: tokio::runtime::Runtime) -> Result<()> {
    let app = adw::Application::builder()
        .application_id("com.google.QuickShare")
        .build();

    let rt_handle = rt.handle().clone();

    app.connect_activate(move |app| {
        let local_ip = get_local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let dev_name = config.device_name.clone();
        let current_download_dir = Arc::new(RwLock::new(config.download_dir.clone()));

        // 1. Bind TCP listener first with fallback if preferred port is busy
        let (listener, actual_port) = match rt_handle.block_on(bind_listener_with_fallback(config.port)) {
            Ok(res) => res,
            Err(e) => {
                error!("Fatal: Failed to bind TCP listener: {:?}", e);
                return;
            }
        };

        info!("TCP Listener successfully bound on 0.0.0.0:{}", actual_port);

        // 2. Start mDNS advertiser with the actual port
        let advertiser = Arc::new(Mutex::new(match MdnsAdvertiser::new() {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create mDNS advertiser: {:?}", e);
                return;
            }
        }));

        let endpoint_id = {
            let adv = advertiser.clone();
            let name = dev_name.clone();
            rt_handle.block_on(async move {
                adv.lock()
                    .await
                    .start_advertising(&name, actual_port, None)
                    .unwrap_or_else(|_| "LNX1".to_string())
            })
        };

        // 3. Start Bluetooth LE Advertiser (UUID 0xFEF3)
        let ble_adv = Arc::new(BleAdvertiser::new());
        if let Err(e) = ble_adv.start_advertising(&endpoint_id, &dev_name) {
            warn!("Failed to start BLE advertiser: {:?}", e);
        }

        // 4. Create UI main window
        let main_window = Rc::new(MainWindow::new(
            app,
            &dev_name,
            config.download_dir.clone(),
            actual_port,
            &local_ip,
            &endpoint_id,
        ));

        // Event channel from background Tokio tasks to GTK UI
        let (app_tx, mut app_rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();
        let (sync_tx, sync_rx) = std::sync::mpsc::channel::<AppEvent>();

        // Bridge Tokio async events into thread-safe sync channel
        rt_handle.spawn(async move {
            while let Some(event) = app_rx.recv().await {
                if sync_tx.send(event).is_err() {
                    break;
                }
            }
        });

        // Drain events directly on GTK main UI thread every 50ms
        let main_window_clone = main_window.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
            while let Ok(event) = sync_rx.try_recv() {
                main_window_clone.handle_event(event);
            }
            glib::ControlFlow::Continue
        });

        // 5. Start mDNS Browser background task
        let browser_tx = app_tx.clone();
        let my_ep = endpoint_id.clone();
        rt_handle.spawn(async move {
            if let Ok(browser) = MdnsBrowser::new() {
                browser
                    .run_loop(Some(my_ep), move |event| {
                        let _ = browser_tx.send(event);
                    })
                    .await;
            }
        });

        // 6. Start Bluetooth LE & Local LAN Peer Scanner background task
        let ble_scan_tx = app_tx.clone();
        rt_handle.spawn(async move {
            BleScanner::run_loop(ble_scan_tx).await;
        });

        // Track active Tokio session tasks for cancellation
        let active_sessions = Arc::new(Mutex::new(HashMap::<u64, tokio::task::AbortHandle>::new()));
        let active_sessions_accept = active_sessions.clone();

        // 7. Start TCP Listener accept loop
        let listener_tx = app_tx.clone();
        let dl_dir_ref = current_download_dir.clone();
        let rt_h = rt_handle.clone();

        rt_handle.spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        info!("Accepted incoming connection from {}", peer_addr);
                        let d_dir = dl_dir_ref.read().await.clone();
                        let s_tx = listener_tx.clone();
                        let task = rt_h.spawn(async move {
                            let session = QuickShareSession::new(stream, d_dir, Some(s_tx));
                            if let Err(e) = session.run().await {
                                error!("Session error with {}: {:?}", peer_addr, e);
                            }
                        });
                        let abort = task.abort_handle();
                        let mut sessions = active_sessions_accept.lock().await;
                        sessions.insert(0, abort);
                    }
                    Err(e) => {
                        error!("TCP accept error: {:?}", e);
                    }
                }
            }
        });

        // Hook up cancel button on incoming transfers
        let active_sessions_cancel = active_sessions.clone();
        main_window.receive_view.on_cancel_transfer(move |_id| {
            let sessions = active_sessions_cancel.clone();
            glib::MainContext::default().spawn_local(async move {
                let mut lock = sessions.lock().await;
                for (_, handle) in lock.drain() {
                    handle.abort();
                    info!("Aborted incoming session task upon user cancel request");
                }
            });
        });

        // Track active send tasks for cancellation
        let active_send_tasks = Arc::new(Mutex::new(HashMap::<u64, tokio::task::AbortHandle>::new()));
        let active_send_cancel = active_send_tasks.clone();
        let active_send_spawn = active_send_tasks.clone();

        // Hook up cancel button on sending transfers
        main_window.send_view.on_cancel_transfer(move |id| {
            let tasks = active_send_cancel.clone();
            glib::MainContext::default().spawn_local(async move {
                let mut lock = tasks.lock().await;
                if let Some(handle) = lock.remove(&id) {
                    handle.abort();
                    info!("Aborted send task for transfer ID {}", id);
                } else {
                    for (_, handle) in lock.drain() {
                        handle.abort();
                    }
                }
            });
        });

        // 8. Connect Send View "Send" action callback
        let send_tx = app_tx.clone();
        let rt_h2 = rt_handle.clone();
        let my_id = endpoint_id.clone();
        let my_name = args.name.clone();

        main_window.send_view.on_send(move |peer, files| {
            if files.is_empty() {
                let _ = send_tx.send(AppEvent::StatusNotification(
                    "No files selected to send! Add files first.".to_string(),
                ));
                return;
            }

            let p_ip = peer.ip;
            let p_port = peer.port;
            let id = my_id.clone();
            let name = my_name.clone();
            let tx = send_tx.clone();
            let send_tracker = active_send_spawn.clone();
            let task_count = files.len();

            let task = rt_h2.spawn(async move {
                let sender = QuickShareSender::new(p_ip, p_port, id, name, files, Some(tx.clone()));
                if let Err(e) = sender.run().await {
                    error!("Send transfer failed: {:?}", e);
                    let _ = tx.send(AppEvent::StatusNotification(format!(
                        "Transfer failed: {}",
                        e
                    )));
                }
            });

            let abort = task.abort_handle();
            let tracker = send_tracker.clone();
            rt_h2.spawn(async move {
                let mut lock = tracker.lock().await;
                for idx in 1..=(task_count as u64) {
                    lock.insert(idx, abort.clone());
                }
            });
        });

        // 9. Connect Settings changes to dynamically update runtime and save to disk
        let adv_save = advertiser.clone();
        let ble_save = ble_adv.clone();
        let dl_save = current_download_dir.clone();
        let rt_h_save = rt_handle.clone();
        let eid_save = endpoint_id.clone();

        main_window.settings_view.on_save(move |cfg| {
            let adv = adv_save.clone();
            let ble = ble_save.clone();
            let dl = dl_save.clone();
            let eid = eid_save.clone();
            let name = cfg.device_name.clone();
            let down_dir = cfg.download_dir.clone();

            rt_h_save.spawn(async move {
                *dl.write().await = down_dir;
                let mut lock = adv.lock().await;
                let _ = lock.start_advertising(&name, actual_port, None);
                let _ = ble.start_advertising(&eid, &name);
                info!("Updated active mDNS & BLE advertisement to device name '{}'", name);
            });
        });

        // 10. Connect Visibility Switch to start/stop mDNS and BLE advertising
        let adv_clone = advertiser.clone();
        let ble_clone = ble_adv.clone();
        let rt_h3 = rt_handle.clone();
        let dev_name = config.device_name.clone();
        let ep_id_clone = endpoint_id.clone();

        main_window
            .receive_view
            .visibility_switch
            .connect_active_notify(move |switch| {
                let is_active = switch.is_active();
                let adv = adv_clone.clone();
                let ble = ble_clone.clone();
                let name = dev_name.clone();
                let eid = ep_id_clone.clone();

                rt_h3.spawn(async move {
                    let mut lock = adv.lock().await;
                    if is_active {
                        let _ = lock.start_advertising(&name, actual_port, None);
                        let _ = ble.start_advertising(&eid, &name);
                    } else {
                        lock.stop_advertising();
                        ble.stop_advertising();
                    }
                });
            });

        main_window.window.present();
    });

    app.run();
    Ok(())
}

async fn run_headless(args: Args, download_path: PathBuf) -> Result<()> {
    println!("================================================================");
    println!("        🚀 QUICK SHARE INTEROPERABLE LINUX CLIENT (CLI)         ");
    println!("================================================================");
    println!("  Device Name:      {}", args.name);
    println!("  Listening Port:   {}", args.port);
    println!("  Downloads Folder: {}", download_path.display());
    println!("================================================================\n");

    // If CLI send was requested
    if let (Some(target), Some(files)) = (args.target, args.send) {
        println!("[SEND] Target: {}", target);
        println!("[SEND] Files:  {:?}", files);

        let (ip_str, port) = if let Some((h, p)) = target.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(8765))
        } else {
            (target.as_str(), 8765)
        };
        let ip: IpAddr = ip_str.parse().context("Invalid target IP address")?;

        let sender = QuickShareSender::new(
            ip,
            port,
            "CLI1".to_string(),
            args.name,
            files,
            None,
        );
        sender.run().await?;
        return Ok(());
    }

    // Default: Headless Receive Daemon
    let (listener, actual_port) = bind_listener_with_fallback(args.port).await?;
    let mut advertiser = MdnsAdvertiser::new()?;
    let endpoint_id = advertiser.start_advertising(&args.name, actual_port, None)?;

    let ble_adv = BleAdvertiser::new();
    let _ = ble_adv.start_advertising(&endpoint_id, &args.name);

    println!("[OK] Registered mDNS service and BLE (0xFEF3) advertiser.");
    println!("[OK] Listening for incoming Quick Share transfers on port {}...", actual_port);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("Accepted connection from {}", peer_addr);
                let d_dir = download_path.clone();
                tokio::spawn(async move {
                    let session = QuickShareSession::new(stream, d_dir, None);
                    if let Err(e) = session.run().await {
                        error!("Session error with {}: {:?}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("TCP accept error: {:?}", e);
            }
        }
    }
}
