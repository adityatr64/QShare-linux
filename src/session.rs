use crate::crypto::SessionKeys;
use crate::events::{AppEvent, DeviceType, DiscoveredPeer};
use crate::proto::wire::{
    connection_response_frame::ResponseStatus,
    connections_v1_frame::FrameType as ConnectionsFrameType,
    paired_key_result_frame::Status as PairedKeyStatus,
    payload_transfer_frame::{
        control_message::EventType as ControlEventType, payload_header::PayloadType,
        ControlMessage, PacketType, PayloadChunk, PayloadHeader,
    },
    sharing_response_frame::Status as SharingResponseStatus,
    sharing_v1_frame::FrameType as SharingFrameType,
    ConnectionResponseFrame, ConnectionsPairedKeyEncryptionFrame, ConnectionsV1Frame,
    DisconnectionFrame, IntroductionFrame, KeepAliveFrame, OfflineFrame, PairedKeyEncryptionFrame,
    PairedKeyResultFrame, PayloadTransferFrame, SharingFrame, SharingResponseFrame, SharingV1Frame,
};
use crate::secure_frame::{decrypt_secure_frame, encrypt_secure_frame, ProtocolRole};
use crate::transport::{read_length_prefixed_frame, write_length_prefixed_frame};
use crate::ukey2::perform_ukey2_handshake_server;
use anyhow::{anyhow, Result};
use prost::Message;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

#[allow(dead_code)]
struct PendingFile {
    name: String,
    size: i64,
    mime_type: String,
    path: PathBuf,
    file: std::fs::File,
    bytes_received: u64,
    start_time: Instant,
}

pub struct QuickShareSession {
    stream: TcpStream,
    download_dir: PathBuf,
    sequence_number: i32,
    files: HashMap<i64, PendingFile>,
    bytes_payload_buffers: HashMap<i64, Vec<u8>>,
    remote_device_name: String,
    transfer_started: bool,
    ui_sender: Option<UnboundedSender<AppEvent>>,
}

impl QuickShareSession {
    pub fn new(
        stream: TcpStream,
        download_dir: PathBuf,
        ui_sender: Option<UnboundedSender<AppEvent>>,
    ) -> Self {
        Self {
            stream,
            download_dir,
            sequence_number: 1, // 1-indexed in Google Nearby Connections
            files: HashMap::new(),
            bytes_payload_buffers: HashMap::new(),
            remote_device_name: "Nearby Device".to_string(),
            transfer_started: false,
            ui_sender,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Accepted incoming connection from {}", self.stream.peer_addr()?);

        // 1. Read unencrypted ConnectionRequest from stream
        let raw_req = read_length_prefixed_frame(&mut self.stream).await?;
        let offline_req = OfflineFrame::decode(raw_req.as_slice())
            .map_err(|e| anyhow!("Failed to decode unencrypted ConnectionRequest: {:?}", e))?;

        let v1_req = offline_req.v1
            .ok_or_else(|| anyhow!("ConnectionRequest missing v1 frame"))?;
        if v1_req.r#type() != ConnectionsFrameType::ConnectionRequest {
            return Err(anyhow!("Expected ConnectionRequest (type 1), got {:?}", v1_req.r#type()));
        }

        if let Some(req) = v1_req.connection_request {
            if let Some(name) = req.endpoint_name {
                if !name.trim().is_empty() {
                    self.remote_device_name = extract_clean_device_name(&name);
                }
            } else if let Some(id) = req.endpoint_id {
                self.remote_device_name = format!("Device {}", id);
            }
            info!("Received ConnectionRequest from '{}'", self.remote_device_name);
        }

        // 2. Perform UKEY2 Handshake as Server
        let keys = perform_ukey2_handshake_server(&mut self.stream).await?;
        info!("UKEY2 Handshake finished. Verification PIN: [{}]", keys.pin);

        // 3. Exchange unencrypted ConnectionResponse with client
        let raw_client_resp = read_length_prefixed_frame(&mut self.stream).await?;
        let client_resp_frame = OfflineFrame::decode(raw_client_resp.as_slice())
            .map_err(|e| anyhow!("Failed to decode unencrypted ConnectionResponse: {:?}", e))?;
        debug!("Received unencrypted ConnectionResponse from client: {:?}", client_resp_frame);

        // Send unencrypted ConnectionResponse ACCEPT
        let resp = ConnectionResponseFrame {
            status: Some(ResponseStatus::Accept as i32),
            handshake_data: None,
            response: Some(ResponseStatus::Accept as i32),
            os_info: Some(crate::proto::wire::OsInfo {
                r#type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
            }),
            multiplex_socket_bitmask: Some(0),
            nearby_connections_version: Some(1),
            safe_to_disconnect_version: None,
            keep_alive_timeout_millis: Some(5000),
            wifi_direct_device_name: None,
        };
        let resp_frame = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::ConnectionResponse as i32),
                connection_request: None,
                connection_response: Some(resp),
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let mut raw_resp_bytes = Vec::new();
        resp_frame.encode(&mut raw_resp_bytes)?;
        write_length_prefixed_frame(&mut self.stream, &raw_resp_bytes).await?;
        info!("Sent unencrypted Connection Response (ACCEPT)");

        // 4. Notify UI that this peer connected and is available (ignore self/loopback connections)
        if let Ok(peer_addr) = self.stream.peer_addr() {
            if !crate::discovery::is_self_ip(&peer_addr.ip()) {
                if let Some(ref tx) = self.ui_sender {
                    let _ = tx.send(AppEvent::PeerDiscovered(DiscoveredPeer {
                        id: format!("phone_{}", peer_addr.ip().to_string().replace('.', "_")),
                        name: self.remote_device_name.clone(),
                        device_type: DeviceType::Phone,
                        ip: peer_addr.ip(),
                        port: 53601,
                    }));
                }
            } else {
                debug!("Ignored incoming connection from self/loopback ({}) for peer discovery", peer_addr.ip());
            }
        }

        // 5. Send initial PairedKeyEncryption SharingFrame to initiate transfer handshake
        let paired_enc = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::PairedKeyEncryption as i32),
                introduction: None,
                connection_response: None,
                paired_key_encryption: Some(PairedKeyEncryptionFrame {
                    secret_id_hash: Some((0..6).map(|_| rand::random::<u8>()).collect()),
                    signed_data: Some((0..72).map(|_| rand::random::<u8>()).collect()),
                    optional_signed_data: None,
                    qr_code_handshake_data: None,
                }),
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        self.send_sharing_frame(&keys, paired_enc).await?;
        info!("Sent encrypted initial PairedKeyEncryption SharingFrame to sender");

        // 6. Main encrypted frame handling loop
        loop {
            let raw_encrypted_frame = match read_length_prefixed_frame(&mut self.stream).await {
                Ok(frame) => frame,
                Err(e) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                            info!("Peer closed connection cleanly.");
                            return Ok(());
                        }
                    }
                    return Err(e);
                }
            };

            let (offline_frame, _seq) = decrypt_secure_frame(
                &keys,
                &raw_encrypted_frame,
                ProtocolRole::Server,
            )?;
            if self.handle_offline_frame(&keys, offline_frame).await? {
                info!("Transfer session finished cleanly. Closing connection.");
                return Ok(());
            }
        }
    }

    async fn handle_offline_frame(
        &mut self,
        keys: &SessionKeys,
        frame: OfflineFrame,
    ) -> Result<bool> {
        let v1 = match frame.v1 {
            Some(v) => v,
            None => return Ok(false),
        };

        match v1.r#type() {
            ConnectionsFrameType::ConnectionRequest => {
                info!("Ignoring duplicate/redundant ConnectionRequest in encrypted stream");
            }

            ConnectionsFrameType::BandwidthUpgradeRetry | ConnectionsFrameType::BandwidthUpgradeNegotiation => {
                debug!("Ignoring bandwidth upgrade negotiation over Wi-Fi LAN");
            }

            ConnectionsFrameType::PairedKeyEncryption => {
                info!("Received ConnectionsPairedKeyEncryption frame from peer, replying with PairedKeyResult (UNABLE)");
                // Respond with PairedKeyResult: UNABLE (3) - indicates no Google Contacts pre-shared keys, standard transfer
                let result = PairedKeyResultFrame {
                    status: Some(PairedKeyStatus::Unable as i32),
                    os_type: Some(1), // Linux
                };
                let mut signed_data = Vec::new();
                result.encode(&mut signed_data)?;

                let encryption_resp = ConnectionsPairedKeyEncryptionFrame {
                    signed_data: Some(signed_data),
                    secret_id_hash: None,
                    optional_signed_data: None,
                };

                let resp_frame = OfflineFrame {
                    version: Some(1),
                    v1: Some(ConnectionsV1Frame {
                        r#type: Some(ConnectionsFrameType::PairedKeyEncryption as i32),
                        connection_request: None,
                        connection_response: None,
                        payload_transfer: None,
                        bandwidth_upgrade_negotiation: None,
                        keep_alive: None,
                        disconnection: None,
                        paired_key_encryption: Some(encryption_resp),
                        authentication_message: None,
                        authentication_result: None,
                    }),
                };
                self.send_encrypted_frame(keys, &resp_frame).await?;
                info!("Sent ConnectionsPairedKeyEncryption result (UNABLE)");
            }

            ConnectionsFrameType::PayloadTransfer => {
                if let Some(transfer) = v1.payload_transfer {
                    return self.handle_payload_transfer(keys, transfer).await;
                }
            }

            ConnectionsFrameType::KeepAlive => {
                let is_ack = v1.keep_alive.as_ref().and_then(|k| k.ack).unwrap_or(false);
                if !is_ack {
                    let keep_alive_ack = OfflineFrame {
                        version: Some(1),
                        v1: Some(ConnectionsV1Frame {
                            r#type: Some(ConnectionsFrameType::KeepAlive as i32),
                            connection_request: None,
                            connection_response: None,
                            payload_transfer: None,
                            bandwidth_upgrade_negotiation: None,
                            keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                            disconnection: None,
                            paired_key_encryption: None,
                            authentication_message: None,
                            authentication_result: None,
                        }),
                    };
                    self.send_encrypted_frame(keys, &keep_alive_ack).await?;
                    tracing::debug!("Replied to KeepAlive with ACK");
                }
            }

            ConnectionsFrameType::Disconnection => {
                info!("Received Disconnection frame from sender");
                if let Some(disc) = v1.disconnection.as_ref() {
                    if disc.request_safe_to_disconnect.unwrap_or(false) {
                        info!("Replying with safe_to_disconnect ACK to sender");
                        let ack_frame = OfflineFrame {
                            version: Some(1),
                            v1: Some(ConnectionsV1Frame {
                                r#type: Some(ConnectionsFrameType::Disconnection as i32),
                                connection_request: None,
                                connection_response: None,
                                payload_transfer: None,
                                bandwidth_upgrade_negotiation: None,
                                keep_alive: None,
                                disconnection: Some(DisconnectionFrame {
                                    request_safe_to_disconnect: None,
                                    ack_safe_to_disconnect: Some(true),
                                }),
                                paired_key_encryption: None,
                                authentication_message: None,
                                authentication_result: None,
                            }),
                        };
                        let _ = self.send_encrypted_frame(keys, &ack_frame).await;
                        let _ = self.stream.flush().await;
                    }
                }
                return Ok(true);
            }

            other => {
                warn!("Received unhandled Connections frame type: {:?}", other);
            }
        }
        Ok(false)
    }

    async fn handle_payload_transfer(
        &mut self,
        keys: &SessionKeys,
        transfer: PayloadTransferFrame,
    ) -> Result<bool> {
        match transfer.packet_type() {
            PacketType::Data => {
                if let Some(header) = transfer.payload_header.as_ref() {
                    let payload_id = header.id.unwrap_or(0);

                    // Case A: Bytes payload (SharingFrame setup frames)
                    if header.r#type() == PayloadType::Bytes {
                        if let Some(chunk) = transfer.payload_chunk {
                            let buf = self.bytes_payload_buffers.entry(payload_id).or_default();
                            if let Some(body) = chunk.body {
                                buf.extend_from_slice(&body);
                            }
                            let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;
                            let total_size = header.total_size.unwrap_or(0) as usize;
                            if is_last || (total_size > 0 && buf.len() >= total_size) {
                                if let Some(complete_body) = self.bytes_payload_buffers.remove(&payload_id) {
                                    if let Ok(sharing_frame) = SharingFrame::decode(&complete_body[..]) {
                                        if let Some(v1) = sharing_frame.v1 {
                                            match v1.r#type() {
                                                SharingFrameType::PairedKeyEncryption => {
                                                    info!("Received PairedKeyEncryption SharingFrame from peer, replying with PairedKeyResult (UNABLE)");
                                                    let result_frame = SharingFrame {
                                                        version: Some(1),
                                                        v1: Some(SharingV1Frame {
                                                            r#type: Some(SharingFrameType::PairedKeyResult as i32),
                                                            introduction: None,
                                                            connection_response: None,
                                                            paired_key_encryption: None,
                                                            paired_key_result: Some(PairedKeyResultFrame {
                                                                status: Some(PairedKeyStatus::Unable as i32),
                                                                os_type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
                                                            }),
                                                            certificate_info: None,
                                                            progress_update: None,
                                                        }),
                                                    };
                                                    self.send_sharing_frame(keys, result_frame).await?;
                                                    info!("Sent PairedKeyResult SharingFrame (UNABLE)");
                                                }
                                                SharingFrameType::PairedKeyResult => {
                                                    info!("Received PairedKeyResult SharingFrame from peer");
                                                }
                                                SharingFrameType::Introduction => {
                                                    if let Some(intro) = v1.introduction {
                                                        self.process_introduction(keys, intro).await?;
                                                    }
                                                }
                                                SharingFrameType::Cancel => {
                                                    info!("Transfer canceled by sender");
                                                }
                                                other => {
                                                    debug!("Received other SharingFrame type: {:?}", other);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return Ok(false);
                    }

                    // Case B: File payload chunk
                    if let Some(chunk) = transfer.payload_chunk {
                        let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;
                        let mut completed_info: Option<(u64, String, std::path::PathBuf)> = None;

                        if let Some(pending) = self.files.get_mut(&payload_id) {
                            if let Some(ref body) = chunk.body {
                                if !body.is_empty() {
                                    let offset = chunk.offset.unwrap_or(pending.bytes_received as i64) as u64;
                                    pending.file.seek(SeekFrom::Start(offset))?;
                                    pending.file.write_all(body)?;
                                    pending.bytes_received += body.len() as u64;

                                    let elapsed = pending.start_time.elapsed().as_secs_f64();
                                    let speed_mbps = if elapsed > 0.05 {
                                        (pending.bytes_received as f64 / 1_048_576.0) / elapsed
                                    } else {
                                        0.0
                                    };

                                    if let Some(ref tx) = self.ui_sender {
                                        let _ = tx.send(AppEvent::TransferProgress {
                                            transfer_id: payload_id as u64,
                                            filename: pending.name.clone(),
                                            transferred: pending.bytes_received,
                                            total: pending.size as u64,
                                            speed_mbps,
                                            is_send: false,
                                        });
                                    }
                                }
                            }

                            let is_complete = is_last || (pending.size > 0 && pending.bytes_received >= pending.size as u64);
                            if is_complete {
                                pending.file.flush()?;
                                completed_info = Some((
                                    pending.bytes_received,
                                    pending.name.clone(),
                                    pending.path.clone(),
                                ));
                            }
                        }

                        if let Some((bytes_received, name, path)) = completed_info {
                            info!("File successfully saved: {} ({} bytes)", path.display(), bytes_received);

                            if let Some(ref tx) = self.ui_sender {
                                let _ = tx.send(AppEvent::TransferCompleted {
                                    transfer_id: payload_id as u64,
                                    filename: name,
                                    file_path: Some(path),
                                    is_send: false,
                                });
                            }

                            // Send PAYLOAD_RECEIVED_ACK
                            let ack = PayloadTransferFrame {
                                packet_type: Some(PacketType::Control as i32),
                                payload_header: None,
                                payload_chunk: None,
                                control_message: Some(ControlMessage {
                                    event: Some(ControlEventType::PayloadReceivedAck as i32),
                                    offset: Some(bytes_received as i64),
                                }),
                            };
                            let ack_frame = OfflineFrame {
                                version: Some(1),
                                v1: Some(ConnectionsV1Frame {
                                    r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                                    connection_request: None,
                                    connection_response: None,
                                    payload_transfer: Some(ack),
                                    bandwidth_upgrade_negotiation: None,
                                    keep_alive: None,
                                    disconnection: None,
                                    paired_key_encryption: None,
                                    authentication_message: None,
                                    authentication_result: None,
                                }),
                            };
                            self.send_encrypted_frame(keys, &ack_frame).await?;
                            self.stream.flush().await?;

                            // Remove completed file from pending files
                            self.files.remove(&payload_id);

                            if self.transfer_started && self.files.is_empty() {
                                info!("All files successfully received! Sending Disconnection frame to sender.");
                                let disconnect_frame = OfflineFrame {
                                    version: Some(1),
                                    v1: Some(ConnectionsV1Frame {
                                        r#type: Some(ConnectionsFrameType::Disconnection as i32),
                                        connection_request: None,
                                        connection_response: None,
                                        payload_transfer: None,
                                        bandwidth_upgrade_negotiation: None,
                                        keep_alive: None,
                                        disconnection: Some(DisconnectionFrame {
                                            request_safe_to_disconnect: None,
                                            ack_safe_to_disconnect: Some(true),
                                        }),
                                        paired_key_encryption: None,
                                        authentication_message: None,
                                        authentication_result: None,
                                    }),
                                };
                                let _ = self.send_encrypted_frame(keys, &disconnect_frame).await;
                                let _ = self.stream.flush().await;
                                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                return Ok(true);
                            }
                        }
                        return Ok(false);
                    }
                }
            }
            PacketType::Control => {
                if let Some(ctrl) = transfer.control_message {
                    info!("Received ControlMessage event: {:?}", ctrl.event());
                }
            }
            PacketType::PayloadAck => {
                info!("Received PayloadAck");
            }
            PacketType::UnknownPacketType => {
                debug!("Received UnknownPacketType");
            }
        }
        Ok(false)
    }


    async fn process_introduction(
        &mut self,
        keys: &SessionKeys,
        intro: IntroductionFrame,
    ) -> Result<()> {
        info!("Received IntroductionFrame with {} files", intro.file_metadata.len());

        let mut file_list = Vec::new();
        let mut total_size = 0u64;

        for meta in &intro.file_metadata {
            let name = meta.name.clone().unwrap_or_else(|| "quickshare_file.bin".to_string());
            let size = meta.size.unwrap_or(0).max(0) as u64;
            total_size += size;
            file_list.push((name, size));
        }

        // Prompt user confirmation if UI is attached
        let accepted = if let Some(ref tx) = self.ui_sender {
            let (accept_tx, accept_rx) = oneshot::channel::<bool>();
            let session_id = rand::random::<u64>();

            info!(
                "Sending IncomingTransferRequest to UI for {} files from '{}' (PIN: {})",
                file_list.len(),
                self.remote_device_name,
                keys.pin
            );

            match tx.send(AppEvent::IncomingTransferRequest {
                session_id,
                peer_name: self.remote_device_name.clone(),
                files: file_list.clone(),
                total_size,
                pin: keys.pin.clone(),
                accept_tx,
            }) {
                Ok(()) => {
                    info!("IncomingTransferRequest sent to UI, waiting for user response...");
                    let mut accept_rx = accept_rx;
                    let user_accepted = loop {
                        tokio::select! {
                            res = &mut accept_rx => {
                                match res {
                                    Ok(ans) => {
                                        info!("User responded to transfer request: accepted={}", ans);
                                        break ans;
                                    }
                                    Err(_) => {
                                        info!("Transfer prompt dismissed or closed, declining transfer");
                                        break false;
                                    }
                                }
                            }
                            frame_res = read_length_prefixed_frame(&mut self.stream) => {
                                match frame_res {
                                    Ok(frame_bytes) => {
                                        if let Ok((offline, _seq)) = decrypt_secure_frame(keys, &frame_bytes, ProtocolRole::Server) {
                                            if let Some(v1) = offline.v1 {
                                                if v1.r#type == Some(ConnectionsFrameType::KeepAlive as i32) {
                                                    let is_ack = v1.keep_alive.as_ref().and_then(|k| k.ack).unwrap_or(false);
                                                    if !is_ack {
                                                        let keep_alive_ack = OfflineFrame {
                                                            version: Some(1),
                                                            v1: Some(ConnectionsV1Frame {
                                                                r#type: Some(ConnectionsFrameType::KeepAlive as i32),
                                                                connection_request: None,
                                                                connection_response: None,
                                                                payload_transfer: None,
                                                                bandwidth_upgrade_negotiation: None,
                                                                keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                                                                disconnection: None,
                                                                paired_key_encryption: None,
                                                                authentication_message: None,
                                                                authentication_result: None,
                                                            }),
                                                        };
                                                        let _ = self.send_encrypted_frame(keys, &keep_alive_ack).await;
                                                        tracing::debug!("Replied to KeepAlive with ACK while awaiting user confirmation");
                                                    }
                                                } else if v1.r#type == Some(ConnectionsFrameType::Disconnection as i32) {
                                                    info!("Sender disconnected while awaiting transfer confirmation");
                                                    break false;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("Connection error while waiting for user confirmation: {:?}", e);
                                        break false;
                                    }
                                }
                            }
                        }
                    };
                    user_accepted
                }
                Err(e) => {
                    info!("Failed to send IncomingTransferRequest to UI ({}), declining transfer", e);
                    false
                }
            }
        } else {
            // Headless daemon auto-accepts
            true
        };

        if !accepted {
            info!("Transfer rejected by user");
            let resp = SharingResponseFrame {
                status: Some(SharingResponseStatus::Reject as i32),
            };
            self.send_sharing_response(keys, resp).await?;
            return Err(anyhow!("Transfer declined by user"));
        }

        info!("Transfer accepted! Preparing target files in {}", self.download_dir.display());
        self.transfer_started = true;

        // Prepare files for receiving
        for meta in intro.file_metadata {
            let name = meta.name.unwrap_or_else(|| "quickshare_file.bin".to_string());
            let size = meta.size.unwrap_or(0);
            let mime = meta.mime_type.unwrap_or_else(|| "application/octet-stream".to_string());
            let payload_id = meta.payload_id.unwrap_or(0);

            let clean_name = Path::new(&name)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or(name.clone());

            let target_path = self.download_dir.join(&clean_name);

            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&target_path)?;

            if let Some(ref tx) = self.ui_sender {
                let _ = tx.send(AppEvent::TransferStarted {
                    transfer_id: payload_id as u64,
                    filename: clean_name.clone(),
                    total: size as u64,
                    is_send: false,
                });
            }

            self.files.insert(
                payload_id,
                PendingFile {
                    name: clean_name,
                    size,
                    mime_type: mime,
                    path: target_path,
                    file,
                    bytes_received: 0,
                    start_time: Instant::now(),
                },
            );
        }

        // Send SharingResponseFrame: ACCEPT
        let resp = SharingResponseFrame {
            status: Some(SharingResponseStatus::Accept as i32),
        };
        self.send_sharing_response(keys, resp).await?;
        info!("Sent ACCEPT sharing response frame to sender");
        Ok(())
    }

    async fn send_sharing_response(
        &mut self,
        keys: &SessionKeys,
        resp: SharingResponseFrame,
    ) -> Result<()> {
        let sharing_resp = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::Response as i32),
                introduction: None,
                connection_response: Some(resp),
                paired_key_encryption: None,
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        self.send_sharing_frame(keys, sharing_resp).await
    }

    async fn send_sharing_frame(
        &mut self,
        keys: &SessionKeys,
        frame: SharingFrame,
    ) -> Result<()> {
        let mut frame_bytes = Vec::new();
        frame.encode(&mut frame_bytes)?;

        let payload_id = rand::random::<i64>().abs();

        // 1. Data chunk: flags=0, offset=0, body=frame_bytes
        let chunk1 = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(payload_id),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(frame_bytes.len() as i64),
                is_sensitive: Some(false),
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(0),
                offset: Some(0),
                body: Some(frame_bytes.clone()),
                index: Some(0),
            }),
            control_message: None,
        };

        let offline_chunk1 = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(chunk1),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        self.send_encrypted_frame(keys, &offline_chunk1).await?;

        // 2. Terminal chunk: flags=1 (LAST_CHUNK), offset=frame_bytes.len(), body=None
        let chunk2 = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(payload_id),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(frame_bytes.len() as i64),
                is_sensitive: Some(false),
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1),
                offset: Some(frame_bytes.len() as i64),
                body: None,
                index: Some(1),
            }),
            control_message: None,
        };

        let offline_chunk2 = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(chunk2),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        self.send_encrypted_frame(keys, &offline_chunk2).await
    }

    async fn send_encrypted_frame(
        &mut self,
        keys: &SessionKeys,
        frame: &OfflineFrame,
    ) -> Result<()> {
        let encrypted_bytes = encrypt_secure_frame(
            keys,
            frame,
            self.sequence_number,
            ProtocolRole::Server,
        )?;
        self.sequence_number += 1;
        write_length_prefixed_frame(&mut self.stream, &encrypted_bytes).await?;
        Ok(())
    }
}

pub fn extract_clean_device_name(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 18 {
        let name_len = bytes[17] as usize;
        if bytes.len() >= 18 + name_len {
            if let Ok(clean) = std::str::from_utf8(&bytes[18..18 + name_len]) {
                let trimmed = clean.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}')
        .collect();
    let trimmed = cleaned.trim();
    if !trimmed.is_empty() {
        trimmed.to_string()
    } else {
        "Android Device".to_string()
    }
}

