mod ble;
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
use discovery::{get_local_ip, MdnsAdvertiser, MdnsBrowser};
use events::AppEvent;
use libadwaita as adw;
use libadwaita::prelude::*;
use sender::QuickShareSender;
use session::QuickShareSession;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use ui::window::MainWindow;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "quickshare-receiver",
    author = "QuickShare Linux Specialist",
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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,quickshare_receiver=debug")),
        )
        .init();

    let args = Args::parse();

    // Determine download destination directory
    let download_path = match args.download_dir.clone() {
        Some(d) => d,
        None => {
            if let Some(user_dirs) = dirs::download_dir() {
                user_dirs
            } else {
                std::env::current_dir()?.join("Downloads")
            }
        }
    };

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
    run_gui(args, download_path, rt)
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

fn run_gui(args: Args, download_path: PathBuf, rt: tokio::runtime::Runtime) -> Result<()> {
    let app = adw::Application::builder()
        .application_id("com.google.QuickShare")
        .build();

    let rt_handle = rt.handle().clone();

    app.connect_activate(move |app| {
        let local_ip = get_local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // 1. Bind TCP listener first with fallback if preferred port is busy
        let (listener, actual_port) = match rt_handle.block_on(bind_listener_with_fallback(args.port)) {
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
            let name = args.name.clone();
            rt_handle.block_on(async move {
                adv.lock()
                    .await
                    .start_advertising(&name, actual_port, None)
                    .unwrap_or_else(|_| "LNX1".to_string())
            })
        };

        // 3. Start Bluetooth LE Advertiser (UUID 0xFEF3)
        let ble_adv = Arc::new(BleAdvertiser::new());
        if let Err(e) = ble_adv.start_advertising(&endpoint_id, &args.name) {
            warn!("Failed to start BLE advertiser: {:?}", e);
        }

        // 4. Create UI main window
        let main_window = Rc::new(MainWindow::new(
            app,
            &args.name,
            download_path.clone(),
            actual_port,
            &local_ip,
            &endpoint_id,
        ));

        // Create event channel between background Tokio tasks and GTK UI
        let (app_tx, mut app_rx) = tokio::sync::mpsc::unbounded_channel::<AppEvent>();

        // Wire GTK main context to handle incoming backend events
        let window_weak = Rc::downgrade(&main_window);
        glib::spawn_future_local(async move {
            while let Some(event) = app_rx.recv().await {
                if let Some(w) = window_weak.upgrade() {
                    w.handle_event(event);
                }
            }
        });

        // 5. Start mDNS Browser background task
        let browser_tx = app_tx.clone();
        rt_handle.spawn(async move {
            if let Ok(browser) = MdnsBrowser::new() {
                browser
                    .run_loop(move |event| {
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

        // 7. Start TCP Listener accept loop
        let listener_tx = app_tx.clone();
        let dest_dir = download_path.clone();
        let rt_h = rt_handle.clone();

        rt_handle.spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        info!("Accepted incoming connection from {}", peer_addr);
                        let d_dir = dest_dir.clone();
                        let s_tx = listener_tx.clone();
                        rt_h.spawn(async move {
                            let session = QuickShareSession::new(stream, d_dir, Some(s_tx));
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

            rt_h2.spawn(async move {
                let sender = QuickShareSender::new(p_ip, p_port, id, name, files, Some(tx.clone()));
                if let Err(e) = sender.run().await {
                    error!("Send transfer failed: {:?}", e);
                    let _ = tx.send(AppEvent::StatusNotification(format!(
                        "Transfer failed: {}",
                        e
                    )));
                }
            });
        });

        // 9. Connect Visibility Switch to start/stop mDNS and BLE advertising
        let adv_clone = advertiser.clone();
        let ble_clone = ble_adv.clone();
        let rt_h3 = rt_handle.clone();
        let dev_name = args.name.clone();
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
        println!("[SUCCESS] CLI send transfer completed successfully!");
        return Ok(());
    }

    // Otherwise run headless receiver daemon
    let (listener, actual_port) = bind_listener_with_fallback(args.port).await?;
    info!("TCP listener bound on 0.0.0.0:{}", actual_port);

    let mut advertiser = MdnsAdvertiser::new()?;
    let endpoint_id = advertiser
        .start_advertising(&args.name, actual_port, None)
        .unwrap_or_else(|_| "LNX1".to_string());

    let ble_adv = BleAdvertiser::new();
    let _ = ble_adv.start_advertising(&endpoint_id, &args.name);

    info!("Headless daemon ready and awaiting incoming transfers via BLE and mDNS...");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("Accepted incoming connection from {}", peer_addr);
                let dest = download_path.clone();
                tokio::spawn(async move {
                    let session = QuickShareSession::new(stream, dest, None);
                    if let Err(e) = session.run().await {
                        error!("Session error with {}: {:?}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting incoming connection: {:?}", e);
            }
        }
    }
}
