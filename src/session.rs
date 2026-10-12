use crate::crypto::SessionKeys;
use crate::events::AppEvent;
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
    IntroductionFrame, OfflineFrame, PairedKeyResultFrame, PayloadTransferFrame, SharingFrame,
    SharingResponseFrame, SharingV1Frame,
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
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::{info, warn};

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
    remote_device_name: String,
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
            sequence_number: 0,
            files: HashMap::new(),
            remote_device_name: "Nearby Device".to_string(),
            ui_sender,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Accepted incoming connection from {}", self.stream.peer_addr()?);

        // 1. UKEY2 Handshake
        let keys = perform_ukey2_handshake_server(&mut self.stream).await?;
        info!("UKEY2 Handshake finished. Verification PIN: [{}]", keys.pin);

        // 2. Main frame handling loop
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
            self.handle_offline_frame(&keys, offline_frame).await?;
        }
    }

    async fn handle_offline_frame(
        &mut self,
        keys: &SessionKeys,
        frame: OfflineFrame,
    ) -> Result<()> {
        let v1 = match frame.v1 {
            Some(v) => v,
            None => return Ok(()),
        };

        match v1.r#type() {
            ConnectionsFrameType::ConnectionRequest => {
                if let Some(req) = v1.connection_request {
                    if let Some(name) = req.endpoint_name {
                        if !name.trim().is_empty() {
                            self.remote_device_name = name;
                        }
                    } else if let Some(id) = req.endpoint_id {
                        self.remote_device_name = format!("Device {}", id);
                    }
                    info!("Incoming connection request from '{}'", self.remote_device_name);
                }

                // Send ConnectionResponse: ACCEPT
                let resp = ConnectionResponseFrame {
                    status: Some(ResponseStatus::Accept as i32),
                    handshake_data: None,
                    response: Some(ResponseStatus::Accept as i32),
                    multiplex_socket_bitmask: None,
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
                self.send_encrypted_frame(keys, &resp_frame).await?;
                info!("Sent Connection Response (ACCEPT)");
            }

            ConnectionsFrameType::PairedKeyEncryption => {
                info!("Received PairedKeyEncryption frame");
                // Respond with PairedKeyResult: SUCCESS
                let result = PairedKeyResultFrame {
                    status: Some(PairedKeyStatus::Success as i32),
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
                info!("Sent PairedKeyEncryption result (SUCCESS)");
            }

            ConnectionsFrameType::PayloadTransfer => {
                if let Some(transfer) = v1.payload_transfer {
                    self.handle_payload_transfer(keys, transfer).await?;
                }
            }

            ConnectionsFrameType::KeepAlive => {
                // KeepAlive acknowledged automatically
            }

            ConnectionsFrameType::Disconnection => {
                info!("Received Disconnection frame from sender");
            }

            other => {
                warn!("Received unhandled Connections frame type: {:?}", other);
            }
        }
        Ok(())
    }

    async fn handle_payload_transfer(
        &mut self,
        keys: &SessionKeys,
        transfer: PayloadTransferFrame,
    ) -> Result<()> {
        match transfer.packet_type() {
            PacketType::Data => {
                if let Some(chunk) = transfer.payload_chunk {
                    if let Some(body) = chunk.body {
                        // Check if this chunk belongs to an active file transfer
                        if let Some(header) = transfer.payload_header.as_ref() {
                            let payload_id = header.id.unwrap_or(0);
                            if let Some(pending) = self.files.get_mut(&payload_id) {
                                let offset = chunk.offset.unwrap_or(0) as u64;
                                pending.file.seek(SeekFrom::Start(offset))?;
                                pending.file.write_all(&body)?;
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

                                let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;
                                if is_last || (pending.size > 0 && pending.bytes_received >= pending.size as u64) {
                                    pending.file.flush()?;
                                    info!(
                                        "File successfully saved: {} ({} bytes)",
                                        pending.path.display(),
                                        pending.bytes_received
                                    );

                                    if let Some(ref tx) = self.ui_sender {
                                        let _ = tx.send(AppEvent::TransferCompleted {
                                            transfer_id: payload_id as u64,
                                            filename: pending.name.clone(),
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
                                            offset: Some(pending.bytes_received as i64),
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
                                }
                                return Ok(());
                            }
                        }

                        // Otherwise, parse as Sharing Introduction Frame (BYTES payload)
                        if let Ok(sharing_frame) = SharingFrame::decode(&body[..]) {
                            if let Some(v1) = sharing_frame.v1 {
                                if v1.r#type() == SharingFrameType::Introduction {
                                    if let Some(intro) = v1.introduction {
                                        self.process_introduction(keys, intro).await?;
                                    }
                                }
                            }
                        }
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
            _ => {}
        }
        Ok(())
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

            let _ = tx.send(AppEvent::IncomingTransferRequest {
                session_id,
                peer_name: self.remote_device_name.clone(),
                files: file_list.clone(),
                total_size,
                pin: keys.pin.clone(),
                accept_tx,
            });

            match accept_rx.await {
                Ok(res) => res,
                Err(_) => false,
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

        let mut sharing_resp_bytes = Vec::new();
        sharing_resp.encode(&mut sharing_resp_bytes)?;

        let payload_frame = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(rand::random::<i64>().abs()),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(sharing_resp_bytes.len() as i64),
                is_sensitive: None,
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1), // LAST_CHUNK
                offset: Some(0),
                body: Some(sharing_resp_bytes),
                index: Some(0),
            }),
            control_message: None,
        };

        let offline_resp = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(payload_frame),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };

        self.send_encrypted_frame(keys, &offline_resp).await
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
